# dnsreaper
 
**Subdomain takeover and DNS misconfiguration scanner.**
 
Detects dangling CNAMEs, ghost NS zones, lame delegations, cloud storage exposure, and already-exploited slots across 25+ fingerprinted services. Built for bug bounty recon and red team engagements.
 
> ⚠️ Work in progress. Core functionality is stable and has confirmed findings in the wild. Edge cases and additional fingerprints are being added actively.
> Hit me up on shadowpentesting@gmail.com if you want any new features added cheers.
 
---
 
## What it finds
 
| Check | Description | Severity |
|---|---|---|
| **CNAME takeover** | Dangling CNAME pointing to an unclaimed slot on a known service | HIGH / MEDIUM |
| **Ghost NS zone** | Domain delegated to NS servers that no longer hold the zone (SERVFAIL) | CRITICAL |
| **Lame delegation** | NS hostnames themselves are NXDOMAIN — registering them = DNS control | HIGH |
| **GCS bucket** | CNAME or GCP LB IP pointing to a non-existent Google Cloud Storage bucket | HIGH |
| **S3 bucket** | CNAME pointing to a non-existent AWS S3 bucket | HIGH |
| **Azure Blob** | CNAME pointing to a non-existent Azure Blob container | HIGH |
| **Already exploited** | Third party has already claimed the slot and is actively serving content | CRITICAL |
| **Already hijacked** | Response body matches known malicious/parked content patterns | CRITICAL |
| **Synthetic ghost zones** | Dead intermediate zones discovered via subdomain SERVFAIL cascade (not in input list) | CRITICAL |
 
---
 
## Fingerprinted services (25+)
 
Azure App Service · Azure Traffic Manager · Azure Blob Storage · Azure CDN · Azure API Management ·
AWS S3 · AWS S3 Static Website · AWS Elastic Beanstalk ·
Google Cloud Storage · Firebase Hosting ·
GitHub Pages · Heroku · WordPress.com · WP Engine ·
Netlify · Vercel · Shopify · Zendesk · Freshdesk ·
HelpScout · Ghost · Fastly · Surge.sh · Render · Fly.io ·
Tumblr · Bitbucket Pages · UserVoice · Cargo · Intercom
 
---
 
## Installation
 
```bash
git clone https://github.com/ShadowByte1/dnsreaper
cd dnsreaper
pip install requests dnspython --break-system-packages
```
 
**Requirements:**
 
```
requests
dnspython
```
 
Python 3.10+ recommended.
 
---
 
## Usage
 
```bash
# Scan a file of subdomains
python3 takeover.py -f subdomains.txt
 
# Single domain
python3 takeover.py -d preview.example.com
 
# Pipe from another tool (e.g. subfinder, httpx)
subfinder -d example.com -silent | python3 takeover.py -
 
# With JSON output and more threads
python3 takeover.py -f subdomains.txt -o results.json --threads 50
 
# Verbose (show all domains, not just vulnerable)
python3 takeover.py -f subdomains.txt --verbose
 
# Only print vulnerable findings (clean output for pipelines)
python3 takeover.py -f subdomains.txt --only-vulnerable
 
# Custom DNS resolver
python3 takeover.py -f subdomains.txt --nameserver 1.1.1.1
```
 
### Input formats
 
The scanner accepts plain domains or URLs — it handles httpx-style output directly:
 
```
sub.example.com
https://sub.example.com
https://sub.example.com [200]
```
 
---
 
## Output
 
```
takeover.py — scanning 1482 domain(s) @ 30 threads
Resolver: 1.1.1.1  Timeout: 8s
 
preview.example.com
  [HIGH] CNAME_TAKEOVER_CANDIDATE
         Service : Azure App Service (FREE (Azure F1 tier))
         Chain   : preview.example.com → example.azurewebsites.net
         PoC     : CONFIRMED ✓
         Match   : Response contains: "404 Web Site not found"
         Claim   : Create App Service with same name at portal.azure.com
 
blog.example.com
  [CRITICAL] GHOST_NS_ZONE_TAKEOVER
         Detail  : blog.example.com returns SERVFAIL — delegated NS servers do not hold the zone
         NS      : ns1.example-hosting.com, ns2.example-hosting.com
         Impact  : Full DNS zone takeover possible — register hosted zone on the same provider
 
────────────────────────────────────────────────────
SCAN SUMMARY
────────────────────────────────────────────────────
  Domains scanned : 1482
  Elapsed         : 94.3s
  Vulnerable      : 4
  ├ CRITICAL      : 1
  ├ HIGH          : 2
  └ MEDIUM        : 1
  Confirmed TOs   : 2
────────────────────────────────────────────────────
```
 
JSON output (via `-o results.json`) includes full finding metadata per domain.
 
---
 
## How it works
 
### CNAME fingerprinting
 
Follows the full CNAME chain for each domain and matches the final target against a database of known-vulnerable service suffixes. HTTP responses are then checked against per-service body fingerprints to confirm the slot is actually unclaimed before reporting — reducing false positives from platforms that return error pages for any unmapped custom domain.
 
### Ghost NS / zone takeover detection
 
Queries each domain for a SERVFAIL response. When detected, it walks up the DNS tree to find the actual dead zone boundary — suppressing cascading SERVFAIL hits from subdomains and reporting only the zone root. This also catches dead intermediate zones that weren't in the input list (synthetic findings).
 
### Already-exploited detection
 
Checks HTTP response bodies for known exploitation indicators — phrases commonly placed by researchers or malicious actors who have already claimed a slot. These are flagged separately as `ALREADY_EXPLOITED_TAKEOVER` at CRITICAL severity.
 
### Cloud bucket checks
 
Validates GCS bucket existence via the GCS JSON API and S3 bucket existence via the S3 XML API — more reliable than HTTP fingerprinting alone. Also detects GCS exposure via GCP Load Balancer A records when no CNAME is present.
 
---
 
## Integration with recon pipelines
 
Works well after subdomain enumeration and HTTP probing:
 
```bash
# Full recon pipeline example
subfinder -d example.com -silent > subs.txt
httpx -l subs.txt -silent -o live.txt
python3 takeover.py -f live.txt -o takeover_results.json --threads 50
```
 
Also compatible with output from: `amass`, `assetfinder`, `dnsx`, `massdns`.
 
---
 
## Flags
 
| Flag | Default | Description |
|---|---|---|
| `-f FILE` | — | Input file (one domain or URL per line) |
| `-d DOMAIN` | — | Single domain to scan |
| `-` | — | Read from stdin |
| `-o FILE` | — | Write JSON results to file |
| `-t / --threads N` | 30 | Concurrent threads |
| `--timeout SEC` | 8 | HTTP and DNS timeout |
| `--nameserver IP` | system | DNS resolver IP |
| `--verbose / -v` | off | Show all domains, not just vulnerable |
| `--only-vulnerable` | off | Suppress clean domains from output |
| `--no-color` | off | Disable ANSI color output |
 
---
 
## Known limitations
 
- GitHub Pages check includes a GitHub API call to verify the user/org exists before reporting — unauthenticated rate limit is 60 req/hr. High-thread scans against many `github.io` CNAMEs may hit this; the tool fails safe (treats rate-limited responses as non-claimable).
- Azure App Service and Traffic Manager NXDOMAIN responses are **not** used as confirmation signals — the slot name stays reserved in Azure's global namespace even when the service is stopped. Only HTTP fingerprints are used.
- AWS ELB CNAMEs are skipped — ELB names encode account ID hashes and are not re-claimable.
- SERVFAIL detection requires raw DNS query capability. Environments that intercept DNS (some VPNs, corporate resolvers) may produce inaccurate results — use `--nameserver` with a reliable public resolver.
 
---
 
## Responsible use
 
This tool is intended for:
 
- Bug bounty research on programs you are authorised to test
- Penetration testing engagements with written scope authorisation
- Security teams auditing their own infrastructure
 
Do not use against targets outside your authorised scope.
 
---
 
## Author
 
[shadowbyte](https://github.com/ShadowByte1) — bug bounty researcher, OSCP
 
---
 
## License
 
MIT
 
