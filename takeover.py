#!/usr/bin/env python3
"""
takeover.py — Subdomain Takeover & DNS Misconfiguration Scanner
================================================================
Checks performed:
  1. CNAME chain resolution → fingerprint against 50+ known vulnerable services
  2. HTTP body fingerprinting → confirm unclaimed slot
  3. Ghost NS / lame delegation → SERVFAIL = full zone takeover possible
  4. GCS bucket existence check → NoSuchBucket via GCS JSON API
  5. S3 bucket existence check → NoSuchBucket via AWS S3 XML API
  6. Azure Blob container check
  7. Heroku app existence check via unauthenticated Platform API
  8. GitHub user/org existence check via GitHub API
  9. Already-hijacked detection — third party claimed the slot and is serving content
     (gambling, pharma spam, XSS payloads, PoC injections, domain parking)

Usage:
  python3 takeover.py -f subdomains.txt
  python3 takeover.py -f subdomains.txt -o results.json --threads 50
  python3 takeover.py -d example.com --verbose
  echo "sub.example.com" | python3 takeover.py -

Author: Shadowbyte
"""

import sys
import argparse
import json
import re
import socket
import ipaddress
import threading
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import dns.resolver
import dns.exception
import dns.rdatatype
import dns.name
import dns.query
import dns.message
import dns.flags

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────────────────────
RESET   = "\033[0m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

def c(color, text): return f"{color}{text}{RESET}"

# Thread-safety for concurrent print output
_print_lock = threading.Lock()

# Zone SERVFAIL cache: avoid re-querying zone apex multiple times
_zone_servfail_cache: dict[str, bool] = {}
_zone_servfail_lock  = threading.Lock()

# Synthetic ghost zone findings: dead intermediate zones discovered via subdomain cascade
# Maps zone_domain → ns_records (list[str])
_synthetic_ghost_zones: dict[str, list] = {}
_synthetic_ghost_lock  = threading.Lock()

# ─────────────────────────────────────────────────────────────
# Takeover fingerprint database
# Each key is matched as a suffix against the final CNAME target
# ─────────────────────────────────────────────────────────────
FINGERPRINTS = {
    # ── Azure ─────────────────────────────────────────────────
    "azurewebsites.net": {
        "service":   "Azure App Service",
        "cost":      "FREE (Azure F1 tier)",
        "severity":  "HIGH",
        "body_must": ["404 Web Site not found", "You do not have permission to view this directory or page"],
        "claim":     "Create App Service with same name at portal.azure.com",
    },
    "cloudapp.azure.com": {
        "service":   "Azure Cloud Service",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["No web app was found for the hostname", "The requested URL was not found on this server", "This Azure cloud service is no longer available"],
        "claim":     "Create Azure Cloud Service with matching hostname",
    },
    "trafficmanager.net": {
        "service":   "Azure Traffic Manager",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["DNS resolution of the Traffic Manager profile", "traffic manager endpoint", "Error 404 - Web app not found"],
        "claim":     "Create Traffic Manager profile with matching endpoint",
        "dns_check": True,
    },
    "blob.core.windows.net": {
        "service":   "Azure Blob Storage",
        "cost":      "FREE (limited storage)",
        "severity":  "HIGH",
        "body_must": ["BlobNotFound", "The specified resource does not exist", "ResourceNotFound"],
        "claim":     "Create storage account with matching blob container",
    },
    "azureedge.net": {
        "service":   "Azure CDN",
        "cost":      "FREE",
        "severity":  "MEDIUM",
        "body_must": ["The CDN endpoint you requested cannot be found", "Endpoint not found", "CDNError"],
        "claim":     "Claim CDN endpoint at portal.azure.com",
    },
    "azure-api.net": {
        "service":   "Azure API Management",
        "cost":      "FREE",
        "severity":  "MEDIUM",
        "body_must": ["404", "ResourceNotFound"],
        "claim":     "Create APIM instance with matching name",
    },

    # ── AWS ───────────────────────────────────────────────────
    "s3.amazonaws.com": {
        "service":   "AWS S3 Bucket",
        "cost":      "FREE (first 12 months)",
        "severity":  "HIGH",
        "body_must": ["NoSuchBucket", "The specified bucket does not exist"],
        "claim":     "Create S3 bucket with matching name",
        "s3_check":  True,
    },
    "s3-website": {
        "service":   "AWS S3 Static Website",
        "cost":      "FREE (first 12 months)",
        "severity":  "HIGH",
        "body_must": ["NoSuchBucket", "The specified bucket does not exist", "Code: NoSuchBucket"],
        "claim":     "Create S3 bucket with static website hosting",
        "s3_check":  True,
    },
    "elasticbeanstalk.com": {
        "service":   "AWS Elastic Beanstalk",
        "cost":      "FREE tier",
        "severity":  "HIGH",
        "body_must": ["404", "No Application"],
        "claim":     "Create EB environment with matching CNAME prefix",
    },
    "elb.amazonaws.com": {
        "service":   "AWS ELB",
        "cost":      "N/A",
        "severity":  "INFO",
        "body_must": [],
        "claim":     "Not directly claimable",
    },

    # ── Google Cloud ──────────────────────────────────────────
    "storage.googleapis.com": {
        "service":   "Google Cloud Storage",
        "cost":      "FREE (GCP free tier)",
        "severity":  "HIGH",
        "body_must": ["NoSuchBucket", "The specified bucket does not exist"],
        "claim":     "Create GCS bucket with matching name",
        "gcs_check": True,
    },
    "c.storage.googleapis.com": {
        "service":   "Google Cloud Storage (CNAME)",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["NoSuchBucket"],
        "claim":     "Create GCS bucket with matching name",
        "gcs_check": True,
    },
    "web.app": {
        "service":   "Firebase Hosting",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Not Found", "404"],
        "claim":     "Deploy Firebase Hosting project with matching site ID",
    },
    "firebaseapp.com": {
        "service":   "Firebase Hosting",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Not Found", "404"],
        "claim":     "Deploy Firebase Hosting project with matching site ID",
    },

    # ── GitHub ────────────────────────────────────────────────
    "github.io": {
        "service":      "GitHub Pages",
        "cost":         "FREE",
        "severity":     "HIGH",
        "body_must":    ["There isn't a GitHub Pages site here", "404 There is nothing here"],
        "claim":        "Create GitHub repo with matching username/org and enable Pages",
        "github_check": True,
    },

    # ── Heroku ────────────────────────────────────────────────
    "herokuapp.com": {
        "service":      "Heroku",
        "cost":         "FREE (free dyno removed, but still claimable)",
        "severity":     "HIGH",
        "body_must":    ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "claim":        "Create Heroku app with matching name",
        "heroku_check": True,   # Use GET api.heroku.com/apps/{name} (unauthenticated, 404=claimable)
    },
    "herokussl.com": {
        "service":      "Heroku SSL",
        "cost":         "FREE",
        "severity":     "HIGH",
        "body_must":    ["No such app"],
        "claim":        "Create Heroku app with matching name",
        "heroku_check": True,
    },

    # ── WordPress ─────────────────────────────────────────────
    "wordpress.com": {
        "service":   "WordPress.com",
        "cost":      "PAID (custom domain ~$4/mo) / FREE (reclaim *.wordpress.com subdomain)",
        "severity":  "HIGH",
        "body_must": ["Error: Active domain connection for this domain not found", "doesn't exist"],
        "http_codes": [404, 410],
        "claim":     "Re-register the wordpress.com subdomain slug",
    },
    "wpengine.com": {
        "service":   "WP Engine",
        "cost":      "PAID (~$25/mo)",
        "severity":  "MEDIUM",
        "body_must": ["Site is not available", "not associated with any active site on the WP Engine platform"],
        "claim":     "Create WP Engine install with matching name",
    },

    # ── Netlify ───────────────────────────────────────────────
    "netlify.app": {
        "service":   "Netlify",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Not Found - Request ID", "netlify"],
        "claim":     "Create Netlify site with matching subdomain",
    },
    "netlify.com": {
        "service":   "Netlify",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Not Found - Request ID"],
        "claim":     "Create Netlify site with matching subdomain",
    },

    # ── Vercel ────────────────────────────────────────────────
    "vercel.app": {
        "service":   "Vercel",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "claim":     "Deploy Vercel project with matching subdomain",
    },
    "now.sh": {
        "service":   "Vercel (legacy)",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["The deployment could not be found"],
        "claim":     "Deploy Vercel project",
    },

    # ── Shopify ───────────────────────────────────────────────
    "myshopify.com": {
        "service":   "Shopify",
        "cost":      "PAID (~$29/mo)",
        "severity":  "MEDIUM",
        "body_must": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "claim":     "Create Shopify store with matching name",
    },

    # ── Zendesk ───────────────────────────────────────────────
    "zendesk.com": {
        "service":   "Zendesk",
        "cost":      "PAID",
        "severity":  "MEDIUM",
        "body_must": ["Help Center Closed", "Oops, this help center no longer exists"],
        "claim":     "Create Zendesk subdomain with matching name",
    },

    # ── Freshdesk ─────────────────────────────────────────────
    "freshdesk.com": {
        "service":   "Freshdesk",
        "cost":      "FREE tier",
        "severity":  "MEDIUM",
        "body_must": ["There is no helpdesk with this URL"],
        "claim":     "Create Freshdesk account with matching subdomain",
    },

    # ── HelpScout ─────────────────────────────────────────────
    "helpscoutdocs.com": {
        "service":   "HelpScout Docs",
        "cost":      "PAID",
        "severity":  "MEDIUM",
        "body_must": ["No settings were found for this company"],
        "claim":     "Create HelpScout Docs site with matching subdomain",
    },

    # ── Ghost ─────────────────────────────────────────────────
    "ghost.io": {
        "service":   "Ghost",
        "cost":      "FREE (ghost.io managed)",
        "severity":  "HIGH",
        "body_must": ["The thing you were looking for is no longer here", "404"],
        "claim":     "Create Ghost publication with matching subdomain",
    },

    # ── Fastly ────────────────────────────────────────────────
    "fastly.net": {
        "service":   "Fastly CDN",
        "cost":      "FREE trial",
        "severity":  "HIGH",
        "body_must": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
        "claim":     "Create Fastly service with matching domain",
    },

    # ── Surge ─────────────────────────────────────────────────
    "surge.sh": {
        "service":   "Surge.sh",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["project not found", "Surge - 404"],
        "claim":     "Deploy Surge project to matching subdomain (surge deploy --domain <target>)",
    },

    # ── Render ────────────────────────────────────────────────
    "onrender.com": {
        "service":   "Render",
        "cost":      "FREE tier",
        "severity":  "HIGH",
        "body_must": ["Service Not Found", "404 - Service Not Found"],
        "claim":     "Create Render service with matching name",
    },

    # ── Fly.io ────────────────────────────────────────────────
    "fly.dev": {
        "service":   "Fly.io",
        "cost":      "FREE tier",
        "severity":  "HIGH",
        "body_must": ["404", "Unknown app"],
        "claim":     "Create Fly.io app with matching name",
    },

    # ── Tumblr ────────────────────────────────────────────────
    "tumblr.com": {
        "service":   "Tumblr",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["There's nothing here.", "Whatever you were looking for doesn't currently exist"],
        "claim":     "Create Tumblr blog with matching custom domain",
    },

    # ── Bitbucket ─────────────────────────────────────────────
    "bitbucket.io": {
        "service":   "Bitbucket Pages",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Repository not found", "The page you have requested does not exist"],
        "claim":     "Create Bitbucket repo with matching Pages config",
    },

    # ── UserVoice ─────────────────────────────────────────────
    "uservoice.com": {
        "service":   "UserVoice",
        "cost":      "PAID",
        "severity":  "MEDIUM",
        "body_must": ["This UserVoice subdomain is currently available"],
        "claim":     "Register UserVoice account with matching subdomain",
    },

    # ── Cargo ─────────────────────────────────────────────────
    "cargocollective.com": {
        "service":   "Cargo Collective",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["404 Not Found"],
        "claim":     "Create Cargo account with matching subdomain",
    },

    # ── Desk.com / Salesforce ─────────────────────────────────
    "desk.com": {
        "service":   "Desk.com (Salesforce)",
        "cost":      "PAID",
        "severity":  "MEDIUM",
        "body_must": ["Sorry, We couldn't find your desk.com"],
        "claim":     "Register Desk.com account with matching subdomain",
    },

    # ── Intercom ─────────────────────────────────────────────
    "intercom.io": {
        "service":   "Intercom",
        "cost":      "PAID",
        "severity":  "MEDIUM",
        "body_must": ["Uh oh. That page doesn't exist."],
        "claim":     "Create Intercom workspace with matching domain",
    },

    # ── Agile CRM ─────────────────────────────────────────────
    "agilecrm.com": {
        "service":   "Agile CRM",
        "cost":      "FREE tier",
        "severity":  "HIGH",
        "body_must": ["Sorry, this page is no longer available."],
        "claim":     "Register Agile CRM account with matching subdomain",
    },

    # ── Anima ─────────────────────────────────────────────────
    "animaapp.io": {
        "service":   "Anima",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["The page you were looking for does not exist."],
        "claim":     "Create Anima project with matching subdomain",
    },

    # ── Discourse ─────────────────────────────────────────────
    "trydiscourse.com": {
        "service":   "Discourse",
        "cost":      "FREE trial",
        "severity":  "HIGH",
        "body_must": [],
        "nxdomain":  True,
        "claim":     "Create Discourse instance with matching subdomain",
    },

    # ── Gemfury ───────────────────────────────────────────────
    "furyns.com": {
        "service":   "Gemfury",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["404: This page could not be found."],
        "claim":     "Create Gemfury account with matching subdomain",
    },

    # ── HatenaBlog ────────────────────────────────────────────
    "hatenablog.com": {
        "service":   "HatenaBlog",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["404 Blog is not found"],
        "claim":     "Register HatenaBlog with matching subdomain",
    },

    # ── Help Juice ────────────────────────────────────────────
    "helpjuice.com": {
        "service":   "Help Juice",
        "cost":      "PAID",
        "severity":  "HIGH",
        "body_must": ["We could not find what you're looking for."],
        "claim":     "Create Help Juice account with matching subdomain",
    },

    # ── JetBrains YouTrack ────────────────────────────────────
    "youtrack.cloud": {
        "service":   "JetBrains YouTrack",
        "cost":      "FREE (up to 10 users)",
        "severity":  "HIGH",
        "body_must": ["is not a registered InCloud YouTrack"],
        "claim":     "Register YouTrack Cloud instance with matching subdomain",
    },

    # ── Ngrok ─────────────────────────────────────────────────
    "ngrok.io": {
        "service":   "Ngrok",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Tunnel "],
        "claim":     "Create Ngrok tunnel with matching subdomain (paid plan)",
    },

    # ── Readme.io ─────────────────────────────────────────────
    "readme.io": {
        "service":   "Readme.io",
        "cost":      "PAID",
        "severity":  "HIGH",
        "body_must": ["The creators of this project are still working on making everything perfect!"],
        "claim":     "Create Readme.io project with matching subdomain",
    },

    # ── Strikingly ────────────────────────────────────────────
    "s.strikinglydns.com": {
        "service":   "Strikingly",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["PAGE NOT FOUND."],
        "claim":     "Create Strikingly site with matching subdomain",
    },

    # ── SurveySparrow ─────────────────────────────────────────
    "surveysparrow.com": {
        "service":   "SurveySparrow",
        "cost":      "FREE trial",
        "severity":  "HIGH",
        "body_must": ["Account not found."],
        "claim":     "Create SurveySparrow account with matching subdomain",
    },

    # ── Uberflip ──────────────────────────────────────────────
    "read.uberflip.com": {
        "service":   "Uberflip",
        "cost":      "PAID",
        "severity":  "HIGH",
        "body_must": ["The URL you've accessed does not provide a hub."],
        "claim":     "Create Uberflip hub with matching domain",
    },

    # ── Uptimerobot ───────────────────────────────────────────
    "stats.uptimerobot.com": {
        "service":   "Uptimerobot",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["page not found"],
        "claim":     "Create Uptimerobot status page with matching subdomain",
    },

    # ── Worksites ─────────────────────────────────────────────
    "worksites.net": {
        "service":   "Worksites",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["Hello! Sorry, but the website you're looking for doesn't exist."],
        "claim":     "Create Worksites account with matching domain",
    },
}

# GCP Load Balancer IP prefixes (anycast, used for GCS backend buckets)
GCP_LB_PREFIXES = [
    "35.190.", "35.191.", "35.201.", "35.220.", "35.241.",
    "34.96.", "34.98.", "34.102.", "34.104.", "34.107.",
    "34.120.", "34.128.", "34.149.", "34.160.",
    "130.211.", "142.250.", "172.217.", "173.194.",
    "216.58.", "216.239.",
]

# CNAME targets that are NOT re-claimable by attackers — suppress DANGLING_CNAME_NXDOMAIN for these
NON_CLAIMABLE_CNAME_SUFFIXES = [
    ".elb.amazonaws.com",          # ELB names encode account ID hash — not re-claimable
    ".execute-api.amazonaws.com",  # API Gateway unique IDs
    ".awsglobalaccelerator.com",   # AWS Global Accelerator
    ".amazonaws.com",              # Generic AWS services (catch-all if above don't match)
]

# Already-taken-over content patterns (non-owner serving malicious/spam content)
# Only include patterns that indicate a *real* hijack — not server misconfigurations.
# Default web server pages (IIS/Nginx/Apache) are NOT included here; they're just unconfigured servers.
#
# Each tuple: (regex_pattern, label_shown_in_output)
# The label should describe WHO/WHAT took it over so the report is actionable.
HIJACKED_PATTERNS = [
    # ── Bug bounty / security researcher PoC injections ──────────
    # Researchers who successfully took over a subdomain often inject one of these as proof
    (r"console\.log\(['\"].*[Tt]akeover|[Hh]ijack|[Pp]o[Cc]|[Bb]ug\s*[Bb]ounty", "Security researcher PoC (console.log injection)"),
    (r"<script[^>]*>\s*alert\s*\(\s*['\"](?:takeover|hijack|xss|poc|owned|pwned|h1|hackerone|bugbounty)['\"]", "Security researcher XSS PoC (alert injection)"),
    (r"document\.title\s*=\s*['\"](?:takeover|hijack|xss|poc|owned|pwned|h1)", "Security researcher PoC (document.title injection)"),
    (r"subdomain.{0,20}takeover|takeover.{0,20}poc|this\s+(?:sub)?domain\s+(?:has\s+been\s+)?(?:taken\s+over|hijacked|claimed)", "Security researcher takeover claim"),
    (r"hackerone|bugcrowd|intigriti|yeswehack|synack.*report|bug\s*bounty\s*(?:poc|proof|claim)", "Bug bounty researcher claim"),
    (r"(?:taken over|hijacked) by [a-zA-Z0-9_-]{3,30}", "Takeover claimed by researcher"),

    # ── Gambling / spam ───────────────────────────────────────────
    (r"เว็บพนัน|คาสิโน|สล็อต|บาคาร่า", "Malicious takeover: Thai gambling site"),
    (r"(?:แทงบอล|เดิมพัน|ทดลองเล่น|สมัครสมาชิก).{0,30}(?:ฟรี|เครดิต|โบนัส)", "Malicious takeover: Thai gambling site"),
    (r"казино|ставки|слоты|покер", "Malicious takeover: Russian gambling site"),
    (r"online.{0,30}casino|gambling.{0,30}bonus|free.{0,30}slots|sports.{0,30}betting", "Malicious takeover: Gambling content"),
    (r"viagra|cialis|pharmacy.*online|buy.*pills.*cheap", "Malicious takeover: Pharma spam"),

    # ── Domain parking ────────────────────────────────────────────
    (r"this domain is for sale|buy this domain|domain.*available.*purchase", "Domain parking: for sale"),
    (r"GoDaddy.*auction|Sedo\.com.*domain|sedoparking", "Domain parking: GoDaddy/Sedo"),
    (r"parkingcrew\.net|bodis\.com|above\.com.*parking", "Domain parking: ParkingCrew/Bodis"),

    # ── Generic hostile content indicators ────────────────────────
    (r"<script[^>]*src=['\"]https?://(?!(?:cdnjs|ajax\.googleapis|code\.jquery|cdn\.jsdelivr|unpkg))[a-z0-9.-]+\.[a-z]{2,}/[^'\"]{0,100}(?:miner|cryptojack|coinhive|coin-hive)", "Malicious takeover: Cryptojacker injected"),
]


# ─────────────────────────────────────────────────────────────
# DNS utilities
# ─────────────────────────────────────────────────────────────

def resolve_cname_chain(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Follow CNAME chain and return all targets."""
    chain = []
    current = domain
    visited = set()
    for _ in range(10):  # max chain depth
        if current in visited:
            break
        visited.add(current)
        try:
            ans = resolver.resolve(current, "CNAME")
            target = str(ans[0].target).rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            break
    return chain


def resolve_a(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Resolve A records."""
    try:
        ans = resolver.resolve(domain, "A")
        return [str(r) for r in ans]
    except Exception:
        return []


def resolve_ns(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Resolve NS records."""
    try:
        ans = resolver.resolve(domain, "NS")
        return [str(r).rstrip(".") for r in ans]
    except Exception:
        return []


def check_nxdomain(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """Return True if domain is NXDOMAIN."""
    try:
        resolver.resolve(domain, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def check_servfail(domain: str, resolver: dns.resolver.Resolver = None) -> bool:
    """Return True if domain returns SERVFAIL (indicates ghost NS / lame delegation)."""
    # Use resolver's nameserver if available, otherwise fall back to subprocess dig
    ns_ip = None
    if resolver and resolver.nameservers:
        ns_ip = resolver.nameservers[0]
    else:
        # Parse system resolv.conf
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        ns_ip = line.split()[1]
                        break
        except Exception:
            pass

    if ns_ip:
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A)
            # Try TCP first (more reliable in restricted envs), then UDP
            try:
                response = dns.query.tcp(request, ns_ip, timeout=5)
            except Exception:
                response = dns.query.udp(request, ns_ip, timeout=5)
            return response.rcode() == dns.rcode.SERVFAIL
        except Exception:
            pass

    # Final fallback: subprocess dig
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "+time=4", domain, "A"],
            capture_output=True, text=True, timeout=8
        )
        # SERVFAIL shows nothing in +short output but status differs
        result2 = subprocess.run(
            ["dig", "+time=4", domain, "A"],
            capture_output=True, text=True, timeout=8
        )
        return "SERVFAIL" in result2.stdout
    except Exception:
        return False


def get_zone_apex(domain: str) -> str:
    """Get zone apex (e.g., sub.example.com → example.com)."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def find_dead_ancestor(domain: str, resolver) -> tuple | None:
    """
    Walk up the DNS tree from domain's immediate parent toward the root.
    Return (ancestor, ns_records) for the HIGHEST (fewest labels) dead ancestor —
    i.e., the actual zone root — stopping when a live zone is found.

    Examples:
      cowgirlscountry.X.addondomain5.alphafx.ca
        → X.addondomain5.alphafx.ca SERVFAILs, addondomain5.alphafx.ca SERVFAILs,
          alphafx.ca is LIVE → returns addondomain5.alphafx.ca (the zone root)
      sub.addondomain01.alphafx.ca
        → addondomain01.alphafx.ca SERVFAILs, alphafx.ca is LIVE
        → returns addondomain01.alphafx.ca
      rmdemofix.alpha.co.uk
        → alpha.co.uk is LIVE → returns None (rmdemofix is the dead zone itself)
    """
    parts = domain.split(".")
    last_dead_zone = None
    last_dead_ns: list = []
    for i in range(1, len(parts)):
        ancestor = ".".join(parts[i:])
        if len(ancestor.split(".")) < 2:
            break  # Never query bare TLDs
        with _zone_servfail_lock:
            if ancestor not in _zone_servfail_cache:
                _zone_servfail_cache[ancestor] = check_servfail(ancestor, resolver)
            is_dead = _zone_servfail_cache[ancestor]
        if is_dead:
            # Keep walking up — there may be a higher dead zone
            last_dead_zone = ancestor
            last_dead_ns = resolve_ns(ancestor, resolver)
        else:
            # Live ancestor found — stop here; anything above is live
            break
    return (last_dead_zone, last_dead_ns) if last_dead_zone else None


def check_ns_live(ns_host: str) -> bool:
    """Check if an NS server actually responds to DNS queries."""
    try:
        ip = socket.gethostbyname(ns_host)
        request = dns.message.make_query("test.invalid", dns.rdatatype.A)
        # Try TCP then UDP
        try:
            dns.query.tcp(request, ip, timeout=4)
            return True
        except Exception:
            dns.query.udp(request, ip, timeout=4)
            return True
    except Exception:
        # Final fallback: dig NS
        try:
            import subprocess
            r = subprocess.run(
                ["dig", "+time=3", "@" + ns_host, "test.invalid", "A"],
                capture_output=True, text=True, timeout=6
            )
            return "REFUSED" in r.stdout or "NOERROR" in r.stdout or "NXDOMAIN" in r.stdout
        except Exception:
            return False


def is_malformed_cname(cname_target: str, source_domain: str) -> bool:
    """
    Return True if a CNAME target looks malformed — i.e., the source domain's
    zone apex is appended to the CNAME value (common DNS misconfiguration).
    Example: source=sub.example.com, cname=okta.com.example.com
    """
    zone = get_zone_apex(source_domain)
    return cname_target.endswith("." + zone) and cname_target != source_domain


def check_ns_resolves(ns_host: str) -> bool:
    """Return True if the NS hostname itself resolves (the NS server exists in DNS)."""
    try:
        socket.gethostbyname(ns_host)
        return True
    except socket.gaierror:
        return False


def is_gcp_lb_ip(ip: str) -> bool:
    """Return True if IP looks like a GCP global load balancer."""
    return any(ip.startswith(prefix) for prefix in GCP_LB_PREFIXES)


# ─────────────────────────────────────────────────────────────
# HTTP / Service checks
# ─────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0; +https://github.com)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

def http_get(url: str, timeout: int = 8, follow_redirects: bool = True) -> tuple[int, str, dict]:
    """Return (status_code, body_text, response_headers)."""
    try:
        r = requests.get(
            url, headers=HEADERS, timeout=timeout,
            verify=False, allow_redirects=follow_redirects,
        )
        return r.status_code, r.text[:8192], dict(r.headers)
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url.replace("https://", "http://"),
                             headers=HEADERS, timeout=timeout,
                             verify=False, allow_redirects=follow_redirects)
            return r.status_code, r.text[:8192], dict(r.headers)
        except Exception:
            return 0, "", {}
    except Exception:
        return 0, "", {}


def check_fingerprint(body: str, status: int, fp: dict) -> bool:
    """Return True if HTTP response matches takeover fingerprint."""
    body_lower = body.lower()
    # Check required body strings
    for phrase in fp.get("body_must", []):
        if phrase.lower() in body_lower:
            return True
    # Check expected status codes (standalone OR as supplement to empty-body responses)
    expected_codes = fp.get("http_codes", [])
    if expected_codes and status in expected_codes:
        # If no body phrases are set, code alone confirms
        if not fp.get("body_must"):
            return True
        # If body is empty/connection dropped, code alone confirms
        if not body.strip():
            return True
    return False


# Phrases commonly placed by attackers who have already exploited a subdomain takeover
ALREADY_EXPLOITED_PHRASES = [
    "takeover by",
    "subdomain takeover",
    "taken over by",
    "hacked by",
    "pwned by",
    "owned by",
    "bug bounty poc",
    "proof of concept takeover",
    "this domain has been claimed",
    "this subdomain has been taken",
    "erfix",                   # known active claimer
    "takeover poc",
    "subdomain poc",
]


def check_already_exploited(body: str) -> str:
    """
    Return the matched phrase if the HTTP response body contains indicators
    that a third party has already claimed/exploited this subdomain.
    Returns empty string if no match.
    """
    body_lower = body.lower()
    for phrase in ALREADY_EXPLOITED_PHRASES:
        if phrase in body_lower:
            return phrase
    return ""


def check_gcs_bucket(bucket_name: str) -> tuple[bool, str]:
    """Check if a GCS bucket exists via the GCS JSON API."""
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}"
    try:
        r = requests.get(url, timeout=8, verify=False, headers=HEADERS)
        if r.status_code == 404:
            # GCS API returns errors as a list: data["error"]["errors"][0]["reason"]
            try:
                data = r.json()
                errors = data.get("error", {}).get("errors", [])
                reason = errors[0].get("reason", "") if errors else data.get("error", {}).get("reason", "")
                if reason == "notFound" or "does not exist" in r.text:
                    return True, "GCS bucket does not exist (404 notFound via GCS JSON API)"
            except Exception:
                if "does not exist" in r.text or "NoSuchBucket" in r.text:
                    return True, "GCS bucket does not exist (404 via GCS API)"
        return False, f"GCS bucket status: {r.status_code}"
    except Exception as e:
        return False, f"GCS check error: {e}"


def check_heroku_app_exists(cname_target: str) -> bool:
    """
    Return True if the Heroku app that owns the CNAME target EXISTS.
    If the app exists, the slot is taken — not claimable.

    Uses the unauthenticated Heroku Platform API:
        GET https://api.heroku.com/apps/{app-name}
        200 / 304 → app exists  → NOT claimable (return True)
        404       → app missing → CLAIMABLE   (return False)

    cname_target example: 'vf-friends-and-family.herokuapp.com'
    """
    parts = cname_target.lower().rstrip(".").split(".")
    # Extract app name: first label of *.herokuapp.com or *.herokussl.com
    if len(parts) < 2 or parts[-2] not in ("herokuapp", "herokussl"):
        return True  # Unrecognised pattern — fail safe
    app_name = parts[0]
    try:
        r = requests.get(
            f"https://api.heroku.com/apps/{app_name}",
            timeout=8,
            headers={
                **HEADERS,
                "Accept": "application/vnd.heroku+json; version=3",
            },
            verify=False,
            allow_redirects=True,
        )
        if r.status_code == 404:
            return False   # App deleted — slot claimable
        if r.status_code in (200, 304):
            return True    # App exists — NOT claimable
        # Any other status (401, 429, 5xx) — fail safe to avoid false positives
        return True
    except Exception:
        return True  # Network error — fail safe


def check_github_user_exists(cname_target: str) -> bool:
    """
    Return True if the GitHub user/org that owns the github.io subdomain EXISTS.
    If the user exists, the Pages namespace is taken — not claimable.
    cname_target example: 'someuser.github.io'
    """
    # Extract username: 'someuser.github.io' → 'someuser'
    parts = cname_target.lower().rstrip(".").split(".")
    if len(parts) < 3 or parts[-2] != "github" or parts[-1] != "io":
        return False
    username = parts[0]
    try:
        r = requests.get(
            f"https://api.github.com/users/{username}",
            timeout=8,
            headers={**HEADERS, "Accept": "application/vnd.github+json"},
            verify=False,
        )
        if r.status_code == 200:
            return True   # User/org confirmed exists — NOT claimable
        if r.status_code == 403:
            # Rate-limited — cannot confirm either way; treat as EXISTS to avoid
            # false positives during high-thread scans (GitHub API: 60 req/hr unauth)
            return True
        return False  # 404 = user doesn't exist → claimable
    except Exception:
        return True  # On network error, fail safe — do NOT report as claimable


def check_s3_bucket(bucket_name: str) -> tuple[bool, str]:
    """Check if an S3 bucket exists (and is unclaimed)."""
    # Clean bucket name (strip www., etc.)
    clean = bucket_name.replace("www.", "")
    url = f"https://{clean}.s3.amazonaws.com/"
    try:
        r = requests.get(url, timeout=8, verify=False, headers=HEADERS)
        if r.status_code == 404 and "NoSuchBucket" in r.text:
            return True, "S3 bucket does not exist (NoSuchBucket)"
        if r.status_code == 403 and "AccessDenied" in r.text:
            return False, "S3 bucket exists but access denied (not claimable)"
        return False, f"S3 status: {r.status_code}"
    except Exception as e:
        return False, f"S3 check error: {e}"


def check_azure_blob(container_name: str) -> tuple[bool, str]:
    """Check for Azure Blob Storage takeover via common account patterns."""
    # Heuristic: try common account name patterns
    # Real check: CNAME to <account>.blob.core.windows.net
    # The container_name IS the full blob URL target
    url = f"https://{container_name}/"
    status, body, _ = http_get(url)
    if status in (404, 400) and any(x in body for x in ["BlobNotFound", "ResourceNotFound", "The specified resource does not exist"]):
        return True, f"Azure Blob resource not found (HTTP {status})"
    return False, f"Azure Blob status: {status}"


def detect_hijacked_content(body: str) -> tuple[bool, str]:
    """Check if response body looks like non-owner malicious/parked content."""
    for pattern, label in HIJACKED_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return True, label
    return False, ""


# ─────────────────────────────────────────────────────────────
# Core scan logic for a single domain
# ─────────────────────────────────────────────────────────────

def scan_domain(domain: str, resolver: dns.resolver.Resolver, verbose: bool = False) -> dict:
    """
    Perform all checks on a single domain.
    Returns a result dict with findings.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return {}

    result = {
        "domain":        domain,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "findings":      [],
        "cname_chain":   [],
        "a_records":     [],
        "ns_records":    [],
        "status":        "clean",
    }

    # ── 1. CNAME chain resolution ─────────────────────────────
    cname_chain = resolve_cname_chain(domain, resolver)
    result["cname_chain"] = cname_chain

    # ── 2. A record resolution ────────────────────────────────
    a_records = resolve_a(domain, resolver)
    result["a_records"] = a_records

    # ── 4. CNAME to NXDOMAIN (dangling) ──────────────────────
    # Removed: DANGLING_CNAME_NXDOMAIN was too noisy — it fired for unclaimable
    # third-party managed hostnames (Akamai, Epsilon, IBM, etc.). Known claimable
    # platforms are handled with confirmed fingerprints in step 5 below.

    # ── 5. CNAME fingerprint matching ─────────────────────────
    seen_services = set()  # deduplicate: only report each service once per domain
    for cname_target in cname_chain:
        matched_service = None
        matched_key = None
        for fp_key, fp_data in FINGERPRINTS.items():
            if cname_target.endswith(fp_key) or fp_key in cname_target:
                matched_service = fp_data
                matched_key = fp_key
                break

        if not matched_service:
            continue

        # Skip if we've already reported this service (or a related Azure service) for this domain
        svc_name = matched_service["service"]
        # Group all Azure services — if any Azure service already matched, skip redundant ones
        svc_group = "Azure" if "Azure" in svc_name else svc_name
        if svc_group in seen_services:
            continue
        seen_services.add(svc_group)
        seen_services.add(svc_name)

        # Skip clearly non-claimable (AWS ELBs etc.)
        if matched_service.get("severity") == "INFO":
            continue

        # HTTP fingerprint check on both the domain and the CNAME target
        finding = {
            "type":         "CNAME_TAKEOVER_CANDIDATE",
            "severity":     matched_service["severity"],
            "service":      matched_service["service"],
            "cost":         matched_service["cost"],
            "cname_target": cname_target,
            "cname_chain":  " → ".join([domain] + cname_chain),
            "claim":        matched_service["claim"],
            "fingerprint_confirmed": False,
            "fingerprint_detail":    "",
        }

        # HTTP check on the subdomain itself
        status, body, headers = http_get(f"https://{domain}/")
        if status == 0:
            status, body, headers = http_get(f"http://{domain}/")

        finding["http_status"] = status
        finding["server_header"] = headers.get("Server", "")

        if check_fingerprint(body, status, matched_service):
            finding["fingerprint_confirmed"] = True
            # Find which phrase matched
            for phrase in matched_service.get("body_must", []):
                if phrase.lower() in body.lower():
                    finding["fingerprint_detail"] = f'Response contains: "{phrase}"'
                    break

        # Also check the CNAME target directly
        if not finding["fingerprint_confirmed"]:
            st2, bd2, _ = http_get(f"https://{cname_target}/")
            if check_fingerprint(bd2, st2, matched_service):
                finding["fingerprint_confirmed"] = True
                for phrase in matched_service.get("body_must", []):
                    if phrase.lower() in bd2.lower():
                        finding["fingerprint_detail"] = f'CNAME target response contains: "{phrase}"'
                        break
                # If confirmed by HTTP status code (e.g., WordPress 410 Gone)
                if not finding["fingerprint_detail"]:
                    ec = matched_service.get("http_codes", [])
                    if ec and st2 in ec:
                        finding["fingerprint_detail"] = f'CNAME target {cname_target} returned HTTP {st2} ({matched_service["service"]} deleted/inactive)'

        # Service-specific API checks
        if matched_service.get("gcs_check") or (not cname_chain and is_gcp_lb_ip(a_records[0] if a_records else "")):
            vuln, msg = check_gcs_bucket(domain)
            if vuln:
                finding["fingerprint_confirmed"] = True
                finding["fingerprint_detail"] = msg

        if matched_service.get("s3_check"):
            vuln, msg = check_s3_bucket(domain)
            if vuln:
                finding["fingerprint_confirmed"] = True
                finding["fingerprint_detail"] = msg

        # NOTE: NXDOMAIN on trafficmanager.net / azurewebsites.net is NOT confirmation.
        # Traffic Manager returns NXDOMAIN when a profile is disabled or has no healthy
        # endpoints — the profile still exists and the name is NOT claimable.
        # Azure App Service returns NXDOMAIN when stopped, but the name stays reserved
        # in Azure's global namespace. Only the HTTP fingerprint is reliable for both.

        if matched_service.get("github_check") and finding["fingerprint_confirmed"]:
            # Verify the GitHub user/org doesn't exist — if they do, Pages namespace is taken
            if check_github_user_exists(cname_target):
                finding["fingerprint_confirmed"] = False
                finding["fingerprint_detail"] = f"GitHub user '{cname_target.split('.')[0]}' exists — Pages namespace taken, not claimable"

        if matched_service.get("heroku_check"):
            # Use Heroku Platform API (unauthenticated):
            # GET api.heroku.com/apps/{name} → 200/304 = app exists (NOT claimable), 404 = claimable
            # This is more reliable than body fingerprinting — Heroku returns 503 "No such app" page
            # only when the app slug is fully deleted; the API check is authoritative.
            app_exists = check_heroku_app_exists(cname_target)
            if app_exists:
                # App still registered on Heroku — slug is taken, not claimable
                finding["fingerprint_confirmed"] = False
                finding["fingerprint_detail"] = (
                    f"Heroku app '{cname_target.split('.')[0]}' confirmed EXISTS via API "
                    f"(api.heroku.com/apps/{cname_target.split('.')[0]} → 200) — slot is taken, not claimable"
                )
            else:
                # App does not exist — confirmed claimable via API
                finding["fingerprint_confirmed"] = True
                finding["fingerprint_detail"] = (
                    f"Heroku app '{cname_target.split('.')[0]}' confirmed DELETED via API "
                    f"(api.heroku.com/apps/{cname_target.split('.')[0]} → 404) — slot is claimable"
                )

        # Don't report if HTTP check shows the service is clearly live and healthy.
        # Any response from the CNAME target (including 4xx from live Azure/CDN services)
        # that doesn't match the takeover fingerprint means the slot is occupied.
        #
        # IMPORTANT: Always verify the CNAME target directly, even when fingerprint was
        # confirmed on the source domain. The source domain check can produce false positives
        # on Azure App Service when the custom domain isn't mapped — the App Service itself
        # returns "404 Web Site not found" for any unregistered custom domain Host header,
        # even though the App Service slot is taken. Checking the target directly (with its
        # own hostname as Host) reveals the real state of the slot.
        st_target, bd_target, _ = http_get(f"https://{cname_target}/")

        # ── Already-exploited check ───────────────────────────────────────
        # If a third party has already claimed the slot and is actively serving
        # content, the service fingerprint won't match (returns 200, not the
        # "unclaimed" error page). Detect this by looking for attacker phrases
        # in both the source domain response and the CNAME target response.
        exploit_phrase = check_already_exploited(body) or check_already_exploited(bd_target)
        if exploit_phrase:
            finding["type"]                 = "ALREADY_EXPLOITED_TAKEOVER"
            finding["severity"]             = "CRITICAL"
            finding["fingerprint_confirmed"] = True
            finding["fingerprint_detail"]   = (
                f'Response contains exploitation indicator: "{exploit_phrase}" — '
                f'a third party has already claimed this slot and is serving content'
            )
            result["findings"].append(finding)
            continue
        # ─────────────────────────────────────────────────────────────────

        target_alive = st_target != 0 and not check_fingerprint(bd_target, st_target, matched_service)
        if target_alive:
            continue  # Slot is occupied — source domain false positive (e.g. custom domain not mapped)

        # Only report confirmed findings — unconfirmed candidates are too noisy and
        # produce false positives on platforms where the slot may still be occupied.
        if not finding["fingerprint_confirmed"]:
            continue

        result["findings"].append(finding)

    # ── 6. GCS via A record (load balancer backend) ───────────
    if not cname_chain and a_records:
        for ip in a_records:
            if is_gcp_lb_ip(ip):
                vuln, msg = check_gcs_bucket(domain)
                if vuln:
                    result["findings"].append({
                        "type":         "GCS_BUCKET_TAKEOVER",
                        "severity":     "HIGH",
                        "service":      "Google Cloud Storage (via GCP Load Balancer)",
                        "cost":         "FREE (GCP free tier)",
                        "detail":       f"A record {ip} is a GCP Load Balancer IP; GCS bucket '{domain}' does not exist",
                        "gcs_api_msg":  msg,
                        "claim":        f"Create public GCS bucket named '{domain}' in any GCP project",
                        "impact":       "LB routes requests to non-existent bucket — attacker can claim bucket and serve arbitrary content",
                    })
                break

    # ── 7. Zone / NS checks ───────────────────────────────────
    # Check for SERVFAIL (ghost NS / lame delegation)
    if check_servfail(domain, resolver):
        # Walk up all ancestors to find the actual dead zone boundary.
        # If a closer ancestor SERVFAILs, this domain is just a cascade — suppress it
        # and record the ancestor as a synthetic finding instead.
        dead = find_dead_ancestor(domain, resolver)
        if dead:
            dead_zone, dead_ns = dead
            with _synthetic_ghost_lock:
                if dead_zone not in _synthetic_ghost_zones:
                    _synthetic_ghost_zones[dead_zone] = dead_ns
            # Suppress this domain's finding — the real finding is the dead ancestor
        else:
            # This domain IS the dead zone (no living ancestor found)
            ns_records = resolve_ns(domain, resolver)
            result["ns_records"] = ns_records
            result["findings"].append({
                "type":       "GHOST_NS_ZONE_TAKEOVER",
                "severity":   "CRITICAL",
                "detail":     f"{domain} returns SERVFAIL — delegated NS servers do not hold the zone",
                "ns_servers": ns_records,
                "impact":     "Full DNS zone takeover possible — register hosted zone on the same provider (e.g., Route53) with matching NS names",
                "claim":      "Create a hosted zone with same NS servers (e.g., AWS Route53) and add matching NS records",
            })
    elif not a_records and not cname_chain:
        # Domain doesn't resolve at all — check if NS servers respond.
        # Use check_ns_resolves (not TCP reachability): if the NS hostname itself is NXDOMAIN
        # it's a truly dead NS (lame delegation). If it resolves but is firewalled, it's live.
        ns_records = resolve_ns(domain, resolver)
        if ns_records:
            result["ns_records"] = ns_records
            dead_ns = [ns for ns in ns_records if not check_ns_resolves(ns)]
            if dead_ns and len(dead_ns) == len(ns_records):
                # All NS hostnames don't exist at all → true lame delegation
                result["findings"].append({
                    "type":      "LAME_NS_DELEGATION",
                    "severity":  "HIGH",
                    "detail":    f"{domain} does not resolve and all NS hostnames are NXDOMAIN: {', '.join(dead_ns)}",
                    "impact":    "Lame delegation — if the NS hostname can be registered, attacker controls DNS for this domain",
                    "claim":     f"Register {dead_ns[0]} and host a DNS server authoritative for {domain}",
                })

    # ── 8. Already-taken-over / misconfigured (non-owner content) ────────────
    if a_records or cname_chain:
        status, body, headers = http_get(f"https://{domain}/")
        if status == 0:
            status, body, headers = http_get(f"http://{domain}/")
        if status not in (0, 403) and body:
            hijacked, label = detect_hijacked_content(body)
            if hijacked:
                result["findings"].append({
                    "type":     "ALREADY_HIJACKED",
                    "severity": "CRITICAL",
                    "detail":   f"Response body matches: {label}",
                    "url":      f"https://{domain}/",
                    "http_status": status,
                    "impact":   "Subdomain serving non-owner content — likely confirmed takeover, report immediately",
                })

    if result["findings"]:
        result["status"] = "VULNERABLE"

    return result


# ─────────────────────────────────────────────────────────────
# Output formatting
# ─────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     CYAN,
}


def print_finding(finding: dict, domain: str):
    sev = finding.get("severity", "INFO")
    color = SEV_COLOR.get(sev, CYAN)
    ftype = finding.get("type", "")

    print(f"  {color}[{sev}]{RESET} {c(BOLD, ftype)}")

    if ftype == "CNAME_TAKEOVER_CANDIDATE":
        print(f"         Service : {finding['service']} ({finding['cost']})")
        print(f"         Chain   : {finding['cname_chain']}")
        confirmed = finding.get("fingerprint_confirmed", False)
        conf_str = c(RED + BOLD, "CONFIRMED ✓") if confirmed else c(YELLOW, "unconfirmed (check manually)")
        print(f"         PoC     : {conf_str}")
        if finding.get("fingerprint_detail"):
            print(f"         Match   : {finding['fingerprint_detail']}")
        print(f"         Claim   : {finding['claim']}")

    elif ftype == "GCS_BUCKET_TAKEOVER":
        print(f"         Service : {finding['service']}")
        print(f"         Detail  : {finding['detail']}")
        print(f"         Claim   : {finding['claim']}")

    elif ftype == "GHOST_NS_ZONE_TAKEOVER":
        print(f"         Detail  : {finding['detail']}")
        print(f"         NS      : {', '.join(finding.get('ns_servers', []))}")
        print(f"         Impact  : {finding['impact']}")

    elif ftype == "LAME_NS_DELEGATION":
        print(f"         Detail  : {finding['detail']}")
        print(f"         Impact  : {finding['impact']}")

    elif ftype == "ALREADY_HIJACKED":
        print(f"         Detail  : {finding['detail']}")
        print(f"         URL     : {finding['url']} (HTTP {finding.get('http_status', '?')})")
        print(f"         Impact  : {finding['impact']}")

    elif ftype == "ALREADY_EXPLOITED_TAKEOVER":
        print(f"         Service : {finding.get('service', 'Unknown')} ({finding.get('cost', '?')})")
        print(f"         Chain   : {finding.get('cname_chain', '')}")
        print(f"         Match   : {finding.get('fingerprint_detail', '')}")
        print(f"         Status  : {c(RED + BOLD, 'ACTIVELY EXPLOITED — third party is serving content')}")

    elif ftype == "DANGLING_CNAME_NXDOMAIN":
        print(f"         Detail  : {finding['detail']}")
        print(f"         Impact  : {finding['impact']}")

    else:
        print(f"         Detail  : {finding.get('detail', '')}")


def print_result(result: dict, verbose: bool = False):
    domain = result.get("domain", "")
    findings = result.get("findings", [])
    cname = result.get("cname_chain", [])
    a_rec = result.get("a_records", [])

    if findings:
        print(f"\n{c(BOLD, domain)}")
        if verbose:
            if cname:
                print(f"  {c(DIM, 'CNAME:')} {' → '.join(cname)}")
            if a_rec:
                print(f"  {c(DIM, 'A    :')} {', '.join(a_rec)}")
        for f in findings:
            print_finding(f, domain)
    elif verbose:
        status_str = c(GREEN, "clean") if not cname else c(DIM, f"CNAME → {cname[-1]}")
        print(f"  {c(DIM, domain)} — {status_str}")


def print_summary(results: list[dict], elapsed: float):
    total   = len(results)
    vulns   = [r for r in results if r.get("status") == "VULNERABLE"]
    crits   = [f for r in vulns for f in r["findings"] if f["severity"] == "CRITICAL"]
    highs   = [f for r in vulns for f in r["findings"] if f["severity"] == "HIGH"]
    meds    = [f for r in vulns for f in r["findings"] if f["severity"] == "MEDIUM"]
    confirmed = [f for r in vulns for f in r["findings"]
                 if f.get("type") == "CNAME_TAKEOVER_CANDIDATE" and f.get("fingerprint_confirmed")]

    print(f"\n{'─'*60}")
    print(c(BOLD, "SCAN SUMMARY"))
    print(f"{'─'*60}")
    print(f"  Domains scanned : {total}")
    print(f"  Elapsed         : {elapsed:.1f}s")
    print(f"  Vulnerable      : {c(RED + BOLD, str(len(vulns)))}")
    print(f"  ├ CRITICAL      : {c(RED + BOLD, str(len(crits)))}")
    print(f"  ├ HIGH          : {c(RED, str(len(highs)))}")
    print(f"  └ MEDIUM        : {c(YELLOW, str(len(meds)))}")
    print(f"  Confirmed TOs   : {c(RED + BOLD, str(len(confirmed)))}")
    print(f"{'─'*60}")

    if vulns:
        print(c(BOLD, "\nVulnerable domains:"))
        for r in vulns:
            sev_max = max(
                (f["severity"] for f in r["findings"]),
                key=lambda s: ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(s),
                default="INFO"
            )
            color = SEV_COLOR.get(sev_max, CYAN)
            types = ", ".join(set(f["type"] for f in r["findings"]))
            print(f"  {color}[{sev_max}]{RESET} {r['domain']} — {types}")


# ─────────────────────────────────────────────────────────────
# Post-processing: false positive reduction
# ─────────────────────────────────────────────────────────────

def deduplicate_zone_findings(results: list[dict]) -> list[dict]:
    """
    Suppress GHOST_NS_ZONE_TAKEOVER findings for subdomains when their
    zone apex is also flagged with GHOST_NS_ZONE_TAKEOVER.

    Example: if telematicsco.net is flagged, suppress all
    *.telematicsco.net findings — they're just cascading SERVFAILs.
    """
    ghost_domains = set(
        r["domain"] for r in results
        if any(f["type"] == "GHOST_NS_ZONE_TAKEOVER" for f in r.get("findings", []))
    )
    for result in results:
        domain = result["domain"]
        new_findings = []
        for finding in result.get("findings", []):
            if finding["type"] != "GHOST_NS_ZONE_TAKEOVER":
                new_findings.append(finding)
                continue
            # Check if any parent zone is already flagged
            parts = domain.split(".")
            parent_flagged = any(
                ".".join(parts[i:]) in ghost_domains and ".".join(parts[i:]) != domain
                for i in range(1, len(parts) - 1)
            )
            if not parent_flagged:
                new_findings.append(finding)
            # else: suppress — parent zone is the real finding
        result["findings"] = new_findings
        if not result["findings"]:
            result["status"] = "clean"
    return results


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def extract_hostname(raw: str) -> str:
    """Extract hostname from a URL or plain domain string."""
    raw = raw.strip()
    if raw.startswith("http"):
        # Strip trailing [status] annotations from httpx output: "https://foo.com [200]"
        raw = re.sub(r'\s+\[\d+\].*$', '', raw)
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or raw
            # Skip bare IPs
            try:
                ipaddress.ip_address(host)
                return ""
            except ValueError:
                return host.lower()
        except ValueError:
            return ""
    # Skip bare IPs
    try:
        ipaddress.ip_address(raw)
        return ""
    except ValueError:
        return raw.lower()


def load_domains(args) -> list[str]:
    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                host = extract_hostname(line)
                if host and not host.startswith("#"):
                    domains.append(host)
    if args.stdin or (not args.domain and not args.file):
        for line in sys.stdin:
            host = extract_hostname(line)
            if host and not host.startswith("#"):
                domains.append(host)
    return list(dict.fromkeys(domains))  # deduplicate preserving order


def main():
    parser = argparse.ArgumentParser(
        description="takeover.py — Subdomain Takeover & DNS Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 takeover.py -f subdomains.txt
  python3 takeover.py -f subdomains.txt -o results.json --threads 50 --verbose
  python3 takeover.py -d sub.example.com
  cat subdomains.txt | python3 takeover.py -
  python3 takeover.py -f live.txt --only-vulnerable
        """,
    )
    parser.add_argument("-f", "--file",    metavar="FILE",   help="File with one domain per line (supports URLs)")
    parser.add_argument("-d", "--domain",  metavar="DOMAIN", help="Single domain to check")
    parser.add_argument("-",  dest="stdin",action="store_true", help="Read from stdin")
    parser.add_argument("-o", "--output",  metavar="FILE",   help="Write JSON results to file")
    parser.add_argument("-t", "--threads", metavar="N",      type=int, default=30, help="Concurrent threads (default: 30)")
    parser.add_argument("--timeout",       metavar="SEC",    type=int, default=8,  help="HTTP/DNS timeout seconds (default: 8)")
    parser.add_argument("--nameserver",    metavar="IP",     default=None,         help="DNS resolver IP (default: system resolver from /etc/resolv.conf)")
    parser.add_argument("--verbose",  "-v", action="store_true", help="Show all domains, not just vulnerable")
    parser.add_argument("--only-vulnerable", action="store_true", help="Only print vulnerable findings")
    parser.add_argument("--no-color",      action="store_true", help="Disable color output")
    args = parser.parse_args()

    if args.no_color:
        global RED, YELLOW, GREEN, CYAN, MAGENTA, BOLD, DIM, RESET
        RED = YELLOW = GREEN = CYAN = MAGENTA = BOLD = DIM = RESET = ""

    domains = load_domains(args)
    if not domains:
        parser.print_help()
        sys.exit(1)

    # Configure resolver
    resolver = dns.resolver.Resolver()
    if args.nameserver:
        resolver.nameservers = [args.nameserver]
    # else: use system resolver from /etc/resolv.conf (default)
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    ns_display = args.nameserver or resolver.nameservers[0]
    print(c(BOLD, f"\ntakeover.py — scanning {len(domains)} domain(s) @ {args.threads} threads"))
    print(c(DIM,  f"Resolver: {ns_display}  Timeout: {args.timeout}s\n"))

    start = datetime.now()
    results = []

    def scan_one(domain):
        result = scan_domain(domain, resolver, verbose=args.verbose)
        with _print_lock:
            print_result(result, verbose=args.verbose and not args.only_vulnerable)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_one, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result()
                if r:
                    results.append(r)
            except Exception as e:
                if args.verbose:
                    with _print_lock:
                        print(f"  {c(DIM, '[ERR]')} {futures[future]}: {e}")

    elapsed = (datetime.now() - start).total_seconds()

    # Inject synthetic ghost zone findings for dead intermediate zones discovered
    # during scan (zones not in the input list but found via subdomain SERVFAIL cascade)
    scanned_domains = {r["domain"] for r in results}
    for zone_domain, ns_recs in _synthetic_ghost_zones.items():
        if zone_domain not in scanned_domains:
            synthetic_result = {
                "domain":    zone_domain,
                "status":    "VULNERABLE",
                "synthetic": True,
                "findings":  [{
                    "type":       "GHOST_NS_ZONE_TAKEOVER",
                    "severity":   "CRITICAL",
                    "detail":     f"{zone_domain} returns SERVFAIL — zone delegation exists but hosted zone has been deleted (discovered via subdomain cascade)",
                    "ns_servers": ns_recs,
                    "impact":     "Full DNS zone takeover possible — register hosted zone on the same provider (e.g., Route53) with matching NS names",
                    "claim":      "Create a hosted zone with same NS servers (e.g., AWS Route53) and add matching NS records",
                }],
            }
            results.append(synthetic_result)
            print_result(synthetic_result, verbose=False)

    # Post-processing: collapse cascading SERVFAIL zone findings
    results = deduplicate_zone_findings(results)

    print_summary(results, elapsed)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(c(DIM, f"\n[+] JSON results written to {args.output}"))


if __name__ == "__main__":
    main()
