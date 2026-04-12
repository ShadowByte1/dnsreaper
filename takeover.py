#!/usr/bin/env python3
"""
takeover.py — Subdomain Takeover & DNS Misconfiguration Scanner
================================================================
Techniques used in active bug bounty research (HackerOne).

Checks performed:
  1. CNAME chain resolution → fingerprint against 25+ known vulnerable services
  2. HTTP body fingerprinting → confirm unclaimed slot
  3. Ghost NS / lame delegation → SERVFAIL = full zone takeover possible
  4. GCS bucket existence check → NoSuchBucket via GCS JSON API
  5. S3 bucket existence check → NoSuchBucket via AWS S3 XML API
  6. Azure Blob container check
  7. Route53 hosted zone ghost check (NS records exist, zone deleted)
  8. Already-exploited detection — third party claimed the slot and is serving content
  9. CNAME to NXDOMAIN (dangling CNAME to deleted host)

Ghost Zone Enrichment (new):
  - DoH-based NS IP extraction (works when raw DNS/53 is firewalled)
  - PTR reverse lookup on NS IPs → awsdns hostnames to match
  - DNS provider identification (Route53, Azure DNS, Cloudflare, etc.)
  - Parent zone vs ghost zone NS cross-comparison (confirms separate deleted zone)
  - Takeover feasibility assessment with attempt estimates
  - AWS CLI claim command pre-built with target NS hostnames
  - Claim loop script auto-generated per finding

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
import dns.rcode

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

# Zone SERVFAIL cache
_zone_servfail_cache: dict[str, bool] = {}
_zone_servfail_lock  = threading.Lock()

# Synthetic ghost zone findings
_synthetic_ghost_zones: dict[str, list] = {}
_synthetic_ghost_lock  = threading.Lock()


# ─────────────────────────────────────────────────────────────
# Ghost Zone Enrichment Module
# ─────────────────────────────────────────────────────────────

# DNS provider patterns: keyed by provider name, values are NS hostname substrings
DNS_PROVIDER_PATTERNS = {
    "Route53":      ["awsdns"],
    "Cloudflare":   ["cloudflare.com"],
    "Google Cloud": ["googledomains.com", "cloud-dns"],
    "Azure DNS":    ["azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info"],
    "DigitalOcean": ["digitalocean.com"],
    "NS1":          ["nsone.net"],
    "Fastly":       ["fastly.net"],
    "Dyn":          ["dynect.net"],
    "Namecheap":    ["registrar-servers.com"],
    "GoDaddy":      ["domaincontrol.com"],
    "Netlify":      ["netlify.com"],
    "Vercel":       ["vercel-dns.com"],
    "Hurricane Electric": ["he.net"],
    "Rage4":        ["rage4.com"],
}

# Provider-specific claim instructions for ghost zones
GHOST_ZONE_CLAIM_GUIDES = {
    "Route53": {
        "method":   "Create Route53 Hosted Zone repeatedly until AWS assigns matching NS servers",
        "note":     "Route53 assigns NS servers randomly from a pool of ~500 per TLD. "
                    "Script a create/check/delete loop until all 4 NS hostnames match. "
                    "Zones deleted within 12 hours are not billed ($0.50/mo otherwise).",
        "feasibility": "HIGH — widely documented, multiple confirmed HackerOne reports",
        "steps": [
            "1. Run the auto-generated claim script below",
            "2. Script creates zones until NS hostnames match the target set",
            "3. Once matched, add TXT proof record",
            "4. Verify with DoH: curl 'https://dns.google/resolve?name=<domain>&type=TXT'",
            "5. Screenshot DNS resolution → submit HackerOne report",
        ],
    },
    "Azure DNS": {
        "method":   "Create Azure DNS Zone — Azure lets you choose the zone name, NS are assigned",
        "note":     "Azure DNS zones use azure-dns.{com,net,org,info} NS servers. "
                    "Unlike Route53, Azure assigns NS servers deterministically based on zone name hash. "
                    "Create the zone and check if assigned NS match.",
        "feasibility": "HIGH — deterministic NS assignment means single attempt may succeed",
        "steps": [
            "1. az dns zone create --resource-group <rg> --name <domain>",
            "2. az network dns zone show --name <domain> --query nameServers",
            "3. Compare assigned NS against target NS hostnames",
            "4. If match: add TXT record and verify",
        ],
    },
    "Cloudflare": {
        "method":   "Add zone to Cloudflare account",
        "note":     "Cloudflare requires domain ownership verification. "
                    "Ghost NS takeover on Cloudflare is generally NOT possible without "
                    "registrar-level control. Investigate further before attempting.",
        "feasibility": "LOW — ownership verification blocks most ghost zone claims",
        "steps": [
            "1. Add site to Cloudflare (cloudflare.com/add-site)",
            "2. Cloudflare will request DNS verification — check if subdomain passes",
            "3. If parent zone delegation is truly abandoned, may succeed",
        ],
    },
    "DigitalOcean": {
        "method":   "Create DigitalOcean DNS domain",
        "note":     "DigitalOcean assigns NS servers ns1/ns2/ns3.digitalocean.com. "
                    "If ghost zone used these exact NS, claim is straightforward.",
        "feasibility": "HIGH — fixed NS servers, single attempt",
        "steps": [
            "1. doctl compute domain create <domain>",
            "2. NS servers are always ns1/ns2/ns3.digitalocean.com",
            "3. Add TXT proof record and verify",
        ],
    },
    "Unknown": {
        "method":   "Investigate NS provider and create matching hosted zone",
        "note":     "Provider could not be identified. Perform PTR lookups on NS IPs "
                    "and research the provider's zone creation process.",
        "feasibility": "UNKNOWN — manual investigation required",
        "steps": [
            "1. PTR lookup each NS IP to identify hostnames",
            "2. Research which DNS provider uses those NS patterns",
            "3. Create account and hosted zone on that provider",
            "4. Verify NS assignment matches ghost NS",
        ],
    },
}


def ptr_lookup_doh(ip: str) -> str:
    """
    Reverse PTR lookup via DoH (Google/Cloudflare).
    Works when raw DNS port 53 is firewalled — uses HTTPS/443.
    """
    parts = ip.split(".")
    arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
    for doh_url in [
        f"https://dns.google/resolve?name={arpa}&type=PTR",
        f"https://cloudflare-dns.com/dns-query?name={arpa}&type=PTR",
    ]:
        try:
            r = requests.get(
                doh_url, timeout=8,
                headers={"Accept": "application/dns-json"}
            )
            data = r.json()
            answers = data.get("Answer", [])
            if answers:
                return answers[0]["data"].rstrip(".")
        except Exception:
            continue
    return ""


def doh_ns_query(domain: str) -> dict:
    """
    Query NS records via DoH. Returns NS names, IPs extracted from EDE errors,
    and SERVFAIL status. Works when port 53 is blocked.

    The extended_dns_errors in SERVFAIL responses expose the exact NS IPs
    that were queried — this is how we identify the ghost zone's NS servers
    even when they refuse all queries.
    """
    result = {"ns_names": [], "ns_ips": [], "status": None}
    for doh_url in [
        f"https://dns.google/resolve?name={domain}&type=NS",
        f"https://cloudflare-dns.com/dns-query?name={domain}&type=NS",
    ]:
        try:
            r = requests.get(
                doh_url, timeout=8,
                headers={"Accept": "application/dns-json"}
            )
            data = r.json()
            result["status"] = data.get("Status")  # 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN

            # NS names from Answer section (present when zone exists and responds)
            for rec in data.get("Answer", []):
                if rec.get("type") == 2:
                    ns = rec["data"].rstrip(".")
                    if ns not in result["ns_names"]:
                        result["ns_names"].append(ns)

            # NS IPs from extended_dns_errors EDE-23 (REFUSED) — present in SERVFAIL
            # Format: "[205.251.198.204] rcode=REFUSED for domain/ns"
            for ede in data.get("extended_dns_errors", []):
                text = ede.get("extra_text", "")
                m = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', text)
                if m:
                    ip = m.group(1)
                    if ip not in result["ns_ips"]:
                        result["ns_ips"].append(ip)

            # Also check Comment field (Cloudflare format)
            comment = data.get("Comment", "")
            if isinstance(comment, list):
                comment = " ".join(comment)
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+):\d+', comment):
                ip = m.group(1)
                if ip not in result["ns_ips"]:
                    result["ns_ips"].append(ip)

            if result["status"] is not None:
                break
        except Exception:
            continue
    return result


def identify_dns_provider(ns_names: list, ns_ips: list) -> str:
    """Identify DNS provider from NS hostnames or IP ranges."""
    all_text = " ".join(ns_names + ns_ips).lower()

    for provider, patterns in DNS_PROVIDER_PATTERNS.items():
        if any(p.lower() in all_text for p in patterns):
            return provider

    # IP range heuristics
    for ip in ns_ips:
        if ip.startswith("205.251."):
            return "Route53"  # AWS Route53 anycast range
        if ip.startswith("173.245.") or ip.startswith("198.41."):
            return "Cloudflare"
        if ip.startswith("216.239.") or ip.startswith("8.8."):
            return "Google Cloud"

    return "Unknown"


def enrich_ghost_zone(domain: str, ns_records_from_scanner: list) -> dict:
    """
    Full enrichment for a GHOST_NS_ZONE_TAKEOVER finding.

    Steps:
      1. Query ghost zone NS via DoH → get NS IPs from EDE errors
      2. Query parent zone NS via DoH → get parent NS IPs for comparison
      3. PTR reverse lookup each ghost NS IP → get awsdns/azure/etc hostnames
      4. Identify DNS provider
      5. Cross-compare ghost vs parent NS IPs (confirms separate deleted zone)
      6. Assess feasibility and generate claim script
    """
    enrichment = {
        "ghost_ns_ips":     [],
        "ghost_ns_names":   [],   # resolved via PTR
        "parent_ns_ips":    [],
        "parent_ns_names":  [],
        "provider":         "Unknown",
        "is_separate_zone": False,
        "feasibility":      "UNKNOWN",
        "claim_guide":      {},
        "claim_script":     "",
        "doh_status":       None,
    }

    # Step 1: DoH query for ghost zone (gets NS IPs from EDE errors on SERVFAIL)
    ghost_info = doh_ns_query(domain)
    enrichment["doh_status"] = ghost_info["status"]
    enrichment["ghost_ns_ips"] = ghost_info["ns_ips"]
    enrichment["ghost_ns_names"] = ghost_info["ns_names"]

    # If DoH got NS names directly (zone partially responds), use those
    # If not, fall back to scanner-provided NS records
    if not enrichment["ghost_ns_names"] and ns_records_from_scanner:
        enrichment["ghost_ns_names"] = ns_records_from_scanner

    # Step 2: Resolve parent zone NS for comparison
    parent_parts = domain.split(".")
    for i in range(1, len(parent_parts) - 1):
        parent = ".".join(parent_parts[i:])
        parent_info = doh_ns_query(parent)
        if parent_info["status"] == 0:  # NOERROR = live parent zone found
            enrichment["parent_ns_ips"]   = parent_info["ns_ips"]
            enrichment["parent_ns_names"] = parent_info["ns_names"]
            break

    # Step 3: PTR reverse lookup ghost NS IPs → get actual NS hostnames
    if enrichment["ghost_ns_ips"] and not enrichment["ghost_ns_names"]:
        for ip in enrichment["ghost_ns_ips"]:
            hostname = ptr_lookup_doh(ip)
            if hostname:
                enrichment["ghost_ns_names"].append(hostname)

    # Step 4: Identify provider
    enrichment["provider"] = identify_dns_provider(
        enrichment["ghost_ns_names"],
        enrichment["ghost_ns_ips"]
    )

    # Step 5: Cross-compare NS IPs
    ghost_set  = set(enrichment["ghost_ns_ips"])
    parent_set = set(enrichment["parent_ns_ips"])
    enrichment["is_separate_zone"] = bool(ghost_set) and not ghost_set.issubset(parent_set)
    enrichment["ns_overlap"] = list(ghost_set & parent_set)

    # Step 6: Feasibility + claim guide
    provider = enrichment["provider"]
    guide = GHOST_ZONE_CLAIM_GUIDES.get(provider, GHOST_ZONE_CLAIM_GUIDES["Unknown"])
    enrichment["claim_guide"] = guide
    enrichment["feasibility"] = guide.get("feasibility", "UNKNOWN")

    # Generate claim script
    enrichment["claim_script"] = _generate_claim_script(
        domain, provider, enrichment["ghost_ns_names"], enrichment["ghost_ns_ips"]
    )

    return enrichment


def _generate_claim_script(domain: str, provider: str, ns_names: list, ns_ips: list) -> str:
    """Generate a provider-specific claim script for the ghost zone."""

    if provider == "Route53":
        # Build target NS set for the loop comparison
        target_ns_str = " ".join(f'"{n}"' for n in ns_names) if ns_names else '"<ns-targets>"'
        target_ns_comment = "\n".join(f"#   {n}  ({ip})" for n, ip in zip(ns_names, ns_ips)) if ns_names else "#   (run PTR lookups first)"

        return f"""#!/usr/bin/env bash
# Route53 Ghost Zone Claim Script
# Target: {domain}
# Ghost NS to match:
{target_ns_comment}

TARGET_NS=({target_ns_str})
DOMAIN="{domain}"
ATTEMPT=0

echo "[*] Starting Route53 ghost zone claim loop for $DOMAIN"
echo "[*] Target NS: ${{TARGET_NS[*]}}"
echo ""

while true; do
    ATTEMPT=$((ATTEMPT + 1))
    printf "[*] Attempt %d — creating hosted zone...\\r" "$ATTEMPT"

    RESULT=$(aws route53 create-hosted-zone \\
        --name "$DOMAIN" \\
        --caller-reference "ghost-$(date +%s%N)" \\
        --output json 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "[!] AWS CLI error — check credentials (aws configure)"
        exit 1
    fi

    ZONE_ID=$(echo "$RESULT" | python3 -c \\
        "import sys,json; print(json.load(sys.stdin)['HostedZone']['Id'].split('/')[-1])")

    ASSIGNED_NS=$(echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ns = sorted(d['DelegationSet']['NameServers'])
print(' '.join(ns))
")

    TARGET_SORTED=$(printf '%s\\n' "${{TARGET_NS[@]}}" | sort | tr '\\n' ' ' | xargs)
    ASSIGNED_SORTED=$(echo "$ASSIGNED_NS" | tr ' ' '\\n' | sort | tr '\\n' ' ' | xargs)

    if [ "$ASSIGNED_SORTED" = "$TARGET_SORTED" ]; then
        echo ""
        echo "[!!!] MATCH on attempt $ATTEMPT — Zone ID: $ZONE_ID"
        echo "[*] Assigned NS: $ASSIGNED_NS"
        echo "[*] Adding TXT proof record..."

        aws route53 change-resource-record-sets \\
            --hosted-zone-id "$ZONE_ID" \\
            --change-batch '{{
                "Changes": [{{
                    "Action": "CREATE",
                    "ResourceRecordSet": {{
                        "Name": "'"$DOMAIN"'",
                        "Type": "TXT",
                        "TTL": 300,
                        "ResourceRecords": [{{"Value": "\\"subdomain-takeover-proof-shadowbyte\\""}}]
                    }}
                }}]
            }}'

        echo ""
        echo "[*] Verify with:"
        echo "    curl -s 'https://dns.google/resolve?name=$DOMAIN&type=TXT' | python3 -m json.tool"
        echo "[*] Zone ID to keep: $ZONE_ID"
        break
    else
        aws route53 delete-hosted-zone --id "$ZONE_ID" > /dev/null 2>&1
        sleep 0.5
    fi
done
"""

    elif provider == "Azure DNS":
        return f"""#!/usr/bin/env bash
# Azure DNS Ghost Zone Claim Script
# Target: {domain}
# Ghost NS: {', '.join(ns_names) if ns_names else 'unknown (run PTR lookups)'}

DOMAIN="{domain}"
RESOURCE_GROUP="ghost-zone-rg"  # Change to your RG

echo "[*] Creating Azure DNS zone for $DOMAIN"
az group create --name "$RESOURCE_GROUP" --location eastus > /dev/null 2>&1

RESULT=$(az dns zone create \\
    --resource-group "$RESOURCE_GROUP" \\
    --name "$DOMAIN" \\
    --output json)

ASSIGNED_NS=$(echo "$RESULT" | python3 -c \\
    "import sys,json; [print(n) for n in json.load(sys.stdin)['nameServers']]")

echo "[*] Azure assigned NS:"
echo "$ASSIGNED_NS"
echo ""
echo "[*] Target NS to match:"
printf '%s\\n' {' '.join(ns_names) if ns_names else '"(unknown)"'}
echo ""
echo "[*] Compare above — if all 4 match, add TXT proof:"
echo "    az network dns record-set txt add-record \\\\"
echo "        --resource-group $RESOURCE_GROUP \\\\"
echo "        --zone-name $DOMAIN \\\\"
echo "        --record-set-name @ \\\\"
echo "        --value 'subdomain-takeover-proof-shadowbyte'"
"""

    elif provider == "DigitalOcean":
        return f"""#!/usr/bin/env bash
# DigitalOcean DNS Ghost Zone Claim Script
# Target: {domain}
# DigitalOcean always uses: ns1/ns2/ns3.digitalocean.com

DOMAIN="{domain}"

echo "[*] Creating DigitalOcean DNS zone for $DOMAIN"
doctl compute domain create "$DOMAIN"

echo "[*] Adding TXT proof record..."
doctl compute domain records create "$DOMAIN" \\
    --record-type TXT \\
    --record-name "@" \\
    --record-data "subdomain-takeover-proof-shadowbyte" \\
    --record-ttl 300

echo "[*] Verify: curl -s 'https://dns.google/resolve?name=$DOMAIN&type=TXT' | python3 -m json.tool"
"""

    else:
        return f"""#!/usr/bin/env bash
# Ghost Zone Claim — Provider: {provider}
# Target: {domain}
# Ghost NS IPs: {', '.join(ns_ips) if ns_ips else 'unknown'}
# Ghost NS Names: {', '.join(ns_names) if ns_names else 'unknown (run PTR lookups)'}
#
# Manual steps:
# 1. Identify the DNS provider from NS hostnames above
# 2. Create an account and hosted zone for: {domain}
# 3. Verify the assigned NS servers match the ghost NS names
# 4. Add TXT record: subdomain-takeover-proof-shadowbyte
# 5. Verify: curl -s 'https://dns.google/resolve?name={domain}&type=TXT' | python3 -m json.tool
echo "Manual investigation required — provider: {provider}"
"""


# ─────────────────────────────────────────────────────────────
# Takeover fingerprint database
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
        "service":   "Heroku",
        "cost":      "FREE (free dyno removed, but still claimable)",
        "severity":  "HIGH",
        "body_must": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "claim":     "Create Heroku app with matching name",
    },
    "herokussl.com": {
        "service":   "Heroku SSL",
        "cost":      "FREE",
        "severity":  "HIGH",
        "body_must": ["No such app"],
        "claim":     "Create Heroku app with matching name",
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
}

# GCP Load Balancer IP prefixes
GCP_LB_PREFIXES = [
    "35.190.", "35.191.", "35.201.", "35.220.", "35.241.",
    "34.96.", "34.98.", "34.102.", "34.104.", "34.107.",
    "34.120.", "34.128.", "34.149.", "34.160.",
    "130.211.", "142.250.", "172.217.", "173.194.",
    "216.58.", "216.239.",
]

NON_CLAIMABLE_CNAME_SUFFIXES = [
    ".elb.amazonaws.com",
    ".execute-api.amazonaws.com",
    ".awsglobalaccelerator.com",
    ".amazonaws.com",
]

HIJACKED_PATTERNS = [
    (r"เว็บพนัน|คาสิโน|สล็อต|บาคาร่า", "Thai gambling site"),
    (r"казино|ставки|слоты|покер", "Russian gambling site"),
    (r"online.{0,30}casino|gambling.{0,30}bonus|free.{0,30}slots|sports.{0,30}betting", "Gambling content"),
    (r"viagra|cialis|pharmacy.*online|buy.*pills.*cheap", "Pharma spam"),
    (r"this domain is for sale|buy this domain|domain.*available.*purchase", "Domain for sale"),
    (r"GoDaddy.*auction|Sedo\.com.*domain|sedoparking", "Domain parking service"),
    (r"parkingcrew\.net|bodis\.com|above\.com.*parking", "Domain parking service"),
    (r"(?:แทงบอล|เดิมพัน|ทดลองเล่น|สมัครสมาชิก).{0,30}(?:ฟรี|เครดิต|โบนัส)", "Thai gambling site (confirmed takeover)"),
]


# ─────────────────────────────────────────────────────────────
# DNS utilities
# ─────────────────────────────────────────────────────────────

def resolve_cname_chain(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    chain = []
    current = domain
    visited = set()
    for _ in range(10):
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
    try:
        ans = resolver.resolve(domain, "A")
        return [str(r) for r in ans]
    except Exception:
        return []


def resolve_ns(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        ans = resolver.resolve(domain, "NS")
        return [str(r).rstrip(".") for r in ans]
    except Exception:
        return []


def check_nxdomain(domain: str, resolver: dns.resolver.Resolver) -> bool:
    try:
        resolver.resolve(domain, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def check_servfail(domain: str, resolver: dns.resolver.Resolver = None) -> bool:
    ns_ip = None
    if resolver and resolver.nameservers:
        ns_ip = resolver.nameservers[0]
    else:
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
            try:
                response = dns.query.tcp(request, ns_ip, timeout=5)
            except Exception:
                response = dns.query.udp(request, ns_ip, timeout=5)
            return response.rcode() == dns.rcode.SERVFAIL
        except Exception:
            pass

    try:
        import subprocess
        result2 = subprocess.run(
            ["dig", "+time=4", domain, "A"],
            capture_output=True, text=True, timeout=8
        )
        return "SERVFAIL" in result2.stdout
    except Exception:
        pass

    # Final fallback: DoH (works when raw DNS port 53 is firewalled)
    try:
        for doh in [
            f"https://dns.google/resolve?name={domain}&type=A",
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
        ]:
            r = requests.get(doh, timeout=8, headers={"Accept": "application/dns-json"})
            data = r.json()
            if data.get("Status") == 2:  # SERVFAIL
                return True
            if data.get("Status") is not None:
                return False  # NOERROR or NXDOMAIN — not a SERVFAIL
    except Exception:
        pass

    return False


def get_zone_apex(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def find_dead_ancestor(domain: str, resolver) -> tuple | None:
    parts = domain.split(".")
    last_dead_zone = None
    last_dead_ns: list = []
    for i in range(1, len(parts)):
        ancestor = ".".join(parts[i:])
        if len(ancestor.split(".")) < 2:
            break
        with _zone_servfail_lock:
            if ancestor not in _zone_servfail_cache:
                _zone_servfail_cache[ancestor] = check_servfail(ancestor, resolver)
            is_dead = _zone_servfail_cache[ancestor]
        if is_dead:
            last_dead_zone = ancestor
            last_dead_ns = resolve_ns(ancestor, resolver)
        else:
            break
    return (last_dead_zone, last_dead_ns) if last_dead_zone else None


def check_ns_live(ns_host: str) -> bool:
    try:
        ip = socket.gethostbyname(ns_host)
        request = dns.message.make_query("test.invalid", dns.rdatatype.A)
        try:
            dns.query.tcp(request, ip, timeout=4)
            return True
        except Exception:
            dns.query.udp(request, ip, timeout=4)
            return True
    except Exception:
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
    zone = get_zone_apex(source_domain)
    return cname_target.endswith("." + zone) and cname_target != source_domain


def check_ns_resolves(ns_host: str) -> bool:
    try:
        socket.gethostbyname(ns_host)
        return True
    except socket.gaierror:
        return False


def is_gcp_lb_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in GCP_LB_PREFIXES)


# ─────────────────────────────────────────────────────────────
# HTTP / Service checks
# ─────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SubdomainTakeoverScanner/1.0; +https://github.com)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

def http_get(url: str, timeout: int = 8, follow_redirects: bool = True) -> tuple[int, str, dict]:
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
    body_lower = body.lower()
    for phrase in fp.get("body_must", []):
        if phrase.lower() in body_lower:
            return True
    expected_codes = fp.get("http_codes", [])
    if expected_codes and status in expected_codes:
        if not fp.get("body_must"):
            return True
        if not body.strip():
            return True
    return False


ALREADY_EXPLOITED_PHRASES = [
    "takeover by", "subdomain takeover", "taken over by",
    "hacked by", "pwned by", "owned by", "bug bounty poc",
    "proof of concept takeover", "this domain has been claimed",
    "this subdomain has been taken", "erfix", "takeover poc", "subdomain poc",
]


def check_already_exploited(body: str) -> str:
    body_lower = body.lower()
    for phrase in ALREADY_EXPLOITED_PHRASES:
        if phrase in body_lower:
            return phrase
    return ""


def check_gcs_bucket(bucket_name: str) -> tuple[bool, str]:
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}"
    try:
        r = requests.get(url, timeout=8, verify=False, headers=HEADERS)
        if r.status_code == 404:
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


def check_github_user_exists(cname_target: str) -> bool:
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
            return True
        if r.status_code == 403:
            return True
        return False
    except Exception:
        return True


def check_s3_bucket(bucket_name: str) -> tuple[bool, str]:
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
    url = f"https://{container_name}/"
    status, body, _ = http_get(url)
    if status in (404, 400) and any(x in body for x in ["BlobNotFound", "ResourceNotFound", "The specified resource does not exist"]):
        return True, f"Azure Blob resource not found (HTTP {status})"
    return False, f"Azure Blob status: {status}"


def detect_hijacked_content(body: str) -> tuple[bool, str]:
    for pattern, label in HIJACKED_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return True, label
    return False, ""


# ─────────────────────────────────────────────────────────────
# Core scan logic
# ─────────────────────────────────────────────────────────────

def scan_domain(domain: str, resolver: dns.resolver.Resolver, verbose: bool = False,
                enrich_ghost: bool = True) -> dict:
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

    cname_chain = resolve_cname_chain(domain, resolver)
    result["cname_chain"] = cname_chain

    a_records = resolve_a(domain, resolver)
    result["a_records"] = a_records

    # ── CNAME fingerprint matching ─────────────────────────
    seen_services = set()
    for cname_target in cname_chain:
        matched_service = None
        matched_key = None
        for fp_key, fp_data in FINGERPRINTS.items():
            # Require proper dot-boundary suffix match to avoid
            # "notfastly.net" matching "fastly.net", etc.
            if cname_target == fp_key or cname_target.endswith("." + fp_key):
                matched_service = fp_data
                matched_key = fp_key
                break

        if not matched_service:
            continue

        svc_name = matched_service["service"]
        svc_group = "Azure" if "Azure" in svc_name else svc_name
        if svc_group in seen_services:
            continue
        seen_services.add(svc_group)
        seen_services.add(svc_name)

        if matched_service.get("severity") == "INFO":
            continue

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

        status, body, headers = http_get(f"https://{domain}/")
        if status == 0:
            status, body, headers = http_get(f"http://{domain}/")

        finding["http_status"] = status
        finding["server_header"] = headers.get("Server", "")

        if check_fingerprint(body, status, matched_service):
            finding["fingerprint_confirmed"] = True
            for phrase in matched_service.get("body_must", []):
                if phrase.lower() in body.lower():
                    finding["fingerprint_detail"] = f'Response contains: "{phrase}"'
                    break

        if not finding["fingerprint_confirmed"]:
            st2, bd2, _ = http_get(f"https://{cname_target}/")
            if check_fingerprint(bd2, st2, matched_service):
                finding["fingerprint_confirmed"] = True
                for phrase in matched_service.get("body_must", []):
                    if phrase.lower() in bd2.lower():
                        finding["fingerprint_detail"] = f'CNAME target response contains: "{phrase}"'
                        break
                if not finding["fingerprint_detail"]:
                    ec = matched_service.get("http_codes", [])
                    if ec and st2 in ec:
                        finding["fingerprint_detail"] = f'CNAME target {cname_target} returned HTTP {st2}'

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

        if matched_service.get("github_check") and finding["fingerprint_confirmed"]:
            if check_github_user_exists(cname_target):
                finding["fingerprint_confirmed"] = False
                finding["fingerprint_detail"] = f"GitHub user '{cname_target.split('.')[0]}' exists — not claimable"

        st_target, bd_target, _ = http_get(f"https://{cname_target}/")

        exploit_phrase = check_already_exploited(body) or check_already_exploited(bd_target)
        if exploit_phrase:
            finding["type"]                 = "ALREADY_EXPLOITED_TAKEOVER"
            finding["severity"]             = "CRITICAL"
            finding["fingerprint_confirmed"] = True
            finding["fingerprint_detail"]   = (
                f'Response contains exploitation indicator: "{exploit_phrase}" — '
                f'a third party has already claimed this slot'
            )
            result["findings"].append(finding)
            continue

        # If CNAME target is unreachable (HTTP 0), we have no evidence the slot
        # is free — suppress unless fingerprint was already confirmed by the
        # source domain check. Avoids FPs on firewalled/CDN-edge targets.
        if st_target == 0 and not finding["fingerprint_confirmed"]:
            continue

        # If target returned a live non-matching response, slot is occupied
        target_alive = st_target not in (0, None) and not check_fingerprint(bd_target, st_target, matched_service)
        if target_alive:
            continue

        if not finding["fingerprint_confirmed"]:
            continue

        result["findings"].append(finding)

    # ── GCS via A record ──────────────────────────────────
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

    # ── Zone / NS checks ──────────────────────────────────
    # Confirm SERVFAIL twice (different queries) to filter transient resolver errors.
    # A single SERVFAIL can be a resolver timeout, NXDOMAIN race, or rate-limit.
    if check_servfail(domain, resolver) and check_servfail(domain, resolver):
        dead = find_dead_ancestor(domain, resolver)
        if dead:
            dead_zone, dead_ns = dead
            with _synthetic_ghost_lock:
                if dead_zone not in _synthetic_ghost_zones:
                    _synthetic_ghost_zones[dead_zone] = dead_ns
        else:
            ns_records = resolve_ns(domain, resolver)
            result["ns_records"] = ns_records

            # Sanity check via DoH: if DoH also returns NXDOMAIN (not SERVFAIL),
            # the domain doesn't exist at all — not a ghost zone, suppress finding.
            doh_status_check = doh_ns_query(domain).get("status")
            if doh_status_check == 3:  # NXDOMAIN
                # Not a ghost zone — subdomain simply doesn't exist
                # Record as informational and skip
                result["findings"].append({
                    "type":     "DNS_NXDOMAIN",
                    "severity": "INFO",
                    "detail":   f"{domain} returns SERVFAIL from local resolver but NXDOMAIN via DoH — domain does not exist, not a ghost zone",
                    "impact":   "No takeover possible — NXDOMAIN confirmed via DoH",
                })
                if result["findings"]:
                    result["status"] = "VULNERABLE"
                return result

            # ── Ghost Zone Enrichment ──────────────────────────
            ghost_enrichment = {}
            if enrich_ghost:
                try:
                    ghost_enrichment = enrich_ghost_zone(domain, ns_records)
                except Exception as e:
                    ghost_enrichment = {"error": str(e)}

            # Confidence scoring: count how many independent signals confirm this
            # is a real ghost zone vs a transient SERVFAIL.
            _conf_signals = []
            _conf_signals.append("SERVFAIL x2 confirmed")  # already checked above
            if doh_status_check == 2:
                _conf_signals.append("DoH also returns SERVFAIL")
            if ns_records:
                _conf_signals.append(f"{len(ns_records)} NS record(s) found in parent zone")

            finding = {
                "type":           "GHOST_NS_ZONE_TAKEOVER",
                "severity":       "CRITICAL",
                "detail":         f"{domain} returns SERVFAIL — delegated NS servers do not hold the zone",
                "ns_servers":     ns_records,
                "impact":         "Full DNS zone takeover possible — register hosted zone on the same provider with matching NS names",
                "claim":          "Create a hosted zone with same NS servers (e.g., AWS Route53) and add matching NS records",
                "conf_signals":   _conf_signals,
                "confidence":     len(_conf_signals),
            }

            # Merge enrichment into finding
            if ghost_enrichment and not ghost_enrichment.get("error"):
                finding["ghost_ns_ips"]      = ghost_enrichment.get("ghost_ns_ips", [])
                finding["ghost_ns_names"]     = ghost_enrichment.get("ghost_ns_names", [])
                finding["parent_ns_names"]    = ghost_enrichment.get("parent_ns_names", [])
                finding["provider"]           = ghost_enrichment.get("provider", "Unknown")
                finding["is_separate_zone"]   = ghost_enrichment.get("is_separate_zone", False)
                finding["feasibility"]        = ghost_enrichment.get("feasibility", "UNKNOWN")
                finding["claim_guide"]        = ghost_enrichment.get("claim_guide", {})
                finding["ns_overlap"]         = ghost_enrichment.get("ns_overlap", [])
                # Override claim with enriched provider-specific instruction
                guide = ghost_enrichment.get("claim_guide", {})
                if guide.get("method"):
                    finding["claim"] = guide["method"]

            # FP guard: if enrichment ran but could NOT confirm a separate zone,
            # downgrade severity — it may be a transient SERVFAIL, not a ghost zone.
            # Only applies when enrichment succeeded (ghost_ns_ips present).
            if (finding.get("ghost_ns_ips") and
                    not finding.get("is_separate_zone", True)):
                finding["severity"] = "HIGH"
                finding["fp_warning"] = (
                    "is_separate_zone=False — ghost NS IPs overlap with parent zone. "
                    "May be a transient SERVFAIL or split-horizon config, not a true ghost zone. "
                    "Verify manually before reporting."
                )

            result["findings"].append(finding)

    elif not a_records and not cname_chain:
        ns_records = resolve_ns(domain, resolver)
        if ns_records:
            result["ns_records"] = ns_records
            dead_ns = [ns for ns in ns_records if not check_ns_resolves(ns)]
            if dead_ns and len(dead_ns) == len(ns_records):
                result["findings"].append({
                    "type":      "LAME_NS_DELEGATION",
                    "severity":  "HIGH",
                    "detail":    f"{domain} does not resolve and all NS hostnames are NXDOMAIN: {', '.join(dead_ns)}",
                    "impact":    "Lame delegation — if the NS hostname can be registered, attacker controls DNS for this domain",
                    "claim":     f"Register {dead_ns[0]} and host a DNS server authoritative for {domain}",
                })

    # ── Already-hijacked ──────────────────────────────────
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


def print_finding(finding: dict, domain: str, save_scripts: bool = False):
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

        # Enhanced enrichment output
        provider = finding.get("provider")
        if provider:
            pcolor = RED + BOLD if provider == "Route53" else YELLOW
            print(f"         Provider: {c(pcolor, provider)}")

        ghost_ns_names = finding.get("ghost_ns_names", [])
        ghost_ns_ips   = finding.get("ghost_ns_ips", [])
        if ghost_ns_names or ghost_ns_ips:
            print(f"         Ghost NS:")
            for name, ip in zip(ghost_ns_names, ghost_ns_ips):
                print(f"           {c(CYAN, name)}  ({ip})")
            # Unmatched extras
            for name in ghost_ns_names[len(ghost_ns_ips):]:
                print(f"           {c(CYAN, name)}")
            for ip in ghost_ns_ips[len(ghost_ns_names):]:
                print(f"           (PTR pending)  ({ip})")

        parent_ns = finding.get("parent_ns_names", [])
        if parent_ns:
            print(f"         Parent NS: {', '.join(parent_ns)}")

        is_sep = finding.get("is_separate_zone")
        if is_sep is not None:
            sep_str = c(RED + BOLD, "YES — confirmed separate deleted zone") if is_sep else c(YELLOW, "NO — same zone (unusual)")
            print(f"         Separate Zone: {sep_str}")

        feasibility = finding.get("feasibility")
        if feasibility:
            fcol = RED + BOLD if "HIGH" in feasibility else YELLOW
            print(f"         Feasibility: {c(fcol, feasibility)}")

        guide = finding.get("claim_guide", {})
        if guide:
            print(f"         Method  : {guide.get('method', '')}")
            if guide.get("note"):
                print(f"         Note    : {c(DIM, guide['note'])}")
            steps = guide.get("steps", [])
            if steps:
                print(f"         Steps   :")
                for step in steps:
                    print(f"                   {step}")

        # Confidence signals
        conf_sigs = finding.get("conf_signals", [])
        conf = finding.get("confidence", 0)
        if conf_sigs:
            conf_col = GREEN if conf >= 3 else YELLOW if conf == 2 else RED
            print(f"         Confidence: {c(conf_col, str(conf))}/3  ({', '.join(conf_sigs)})")

        # FP warning (shown when is_separate_zone could not be confirmed)
        fp_warn = finding.get("fp_warning", "")
        if fp_warn:
            print(f"         {c(YELLOW, '⚠ FP RISK :')} {fp_warn}")

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
# Post-processing
# ─────────────────────────────────────────────────────────────

def deduplicate_zone_findings(results: list[dict]) -> list[dict]:
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
            parts = domain.split(".")
            parent_flagged = any(
                ".".join(parts[i:]) in ghost_domains and ".".join(parts[i:]) != domain
                for i in range(1, len(parts) - 1)
            )
            if not parent_flagged:
                new_findings.append(finding)
        result["findings"] = new_findings
        if not result["findings"]:
            result["status"] = "clean"
    return results


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def extract_hostname(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("http"):
        raw = re.sub(r'\s+\[\d+\].*$', '', raw)
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or raw
            try:
                ipaddress.ip_address(host)
                return ""
            except ValueError:
                return host.lower()
        except ValueError:
            return ""
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
    return list(dict.fromkeys(domains))


def main():
    parser = argparse.ArgumentParser(
        description="takeover.py — Subdomain Takeover & DNS Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 takeover.py -f subdomains.txt
  python3 takeover.py -f subdomains.txt -o results.json --threads 50 --verbose
  python3 takeover.py -d preview.example.com
  cat subdomains.txt | python3 takeover.py -
  python3 takeover.py -f live.txt --only-vulnerable
  python3 takeover.py -d sub.example.com --no-enrich   # skip ghost zone enrichment
        """,
    )
    parser.add_argument("-f", "--file",       metavar="FILE",   help="File with one domain per line")
    parser.add_argument("-d", "--domain",     metavar="DOMAIN", help="Single domain to check")
    parser.add_argument("-",  dest="stdin",   action="store_true", help="Read from stdin")
    parser.add_argument("-o", "--output",     metavar="FILE",   help="Write JSON results to file")
    parser.add_argument("-t", "--threads",    metavar="N",      type=int, default=30, help="Concurrent threads (default: 30)")
    parser.add_argument("--timeout",          metavar="SEC",    type=int, default=8,  help="HTTP/DNS timeout (default: 8)")
    parser.add_argument("--nameserver",       metavar="IP",     default=None,         help="DNS resolver IP")
    parser.add_argument("--verbose",  "-v",   action="store_true", help="Show all domains")
    parser.add_argument("--only-vulnerable",  action="store_true", help="Only print vulnerable findings")
    parser.add_argument("--no-color",         action="store_true", help="Disable color output")
    parser.add_argument("--no-enrich",        action="store_true", help="Skip ghost zone NS enrichment (faster, less info)")
    args = parser.parse_args()

    if args.no_color:
        global RED, YELLOW, GREEN, CYAN, MAGENTA, BOLD, DIM, RESET
        RED = YELLOW = GREEN = CYAN = MAGENTA = BOLD = DIM = RESET = ""

    domains = load_domains(args)
    if not domains:
        parser.print_help()
        sys.exit(1)

    resolver = dns.resolver.Resolver(configure=False)
    if args.nameserver:
        resolver.nameservers = [args.nameserver]
    else:
        try:
            sys_res = dns.resolver.Resolver()
            resolver.nameservers = sys_res.nameservers
        except Exception:
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    ns_display = args.nameserver or resolver.nameservers[0]
    enrich = not args.no_enrich

    print(c(BOLD, f"\ntakeover.py — scanning {len(domains)} domain(s) @ {args.threads} threads"))
    print(c(DIM,  f"Resolver: {ns_display}  Timeout: {args.timeout}s  Ghost enrichment: {'ON' if enrich else 'OFF'}\n"))

    start = datetime.now()
    results = []

    def scan_one(domain):
        result = scan_domain(domain, resolver, verbose=args.verbose, enrich_ghost=enrich)
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

    # Inject synthetic ghost zone findings
    scanned_domains = {r["domain"] for r in results}
    for zone_domain, ns_recs in _synthetic_ghost_zones.items():
        if zone_domain not in scanned_domains:
            # Enrich synthetic findings too
            ghost_enrichment = {}
            if enrich:
                try:
                    ghost_enrichment = enrich_ghost_zone(zone_domain, ns_recs)
                except Exception:
                    pass

            finding = {
                "type":       "GHOST_NS_ZONE_TAKEOVER",
                "severity":   "CRITICAL",
                "detail":     f"{zone_domain} returns SERVFAIL — zone delegation exists but hosted zone deleted (discovered via subdomain cascade)",
                "ns_servers": ns_recs,
                "impact":     "Full DNS zone takeover possible — register hosted zone on the same provider with matching NS names",
                "claim":      "Create a hosted zone with same NS servers (e.g., AWS Route53) and add matching NS records",
            }
            if ghost_enrichment and not ghost_enrichment.get("error"):
                finding.update({
                    "ghost_ns_ips":    ghost_enrichment.get("ghost_ns_ips", []),
                    "ghost_ns_names":  ghost_enrichment.get("ghost_ns_names", []),
                    "parent_ns_names": ghost_enrichment.get("parent_ns_names", []),
                    "provider":        ghost_enrichment.get("provider", "Unknown"),
                    "is_separate_zone":ghost_enrichment.get("is_separate_zone", False),
                    "feasibility":     ghost_enrichment.get("feasibility", "UNKNOWN"),
                    "claim_guide":     ghost_enrichment.get("claim_guide", {}),
                })

            synthetic_result = {
                "domain":    zone_domain,
                "status":    "VULNERABLE",
                "synthetic": True,
                "findings":  [finding],
            }
            results.append(synthetic_result)
            print_result(synthetic_result, verbose=False)

    results = deduplicate_zone_findings(results)
    print_summary(results, elapsed)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(c(DIM, f"\n[+] JSON results written to {args.output}"))


if __name__ == "__main__":
    main()
