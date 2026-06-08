# Azure CIS Benchmark Assessment

A single-file Bash tool that audits an Azure subscription against the [CIS Microsoft Azure Foundations Benchmark **v6.0.0**](https://www.cisecurity.org/benchmark/azure) and produces a pentest-ready report in both HTML and JSON. Every check captures the exact command run and its raw output as a traceable evidence artifact.

Built for read-only security assessments — it makes no changes to the target environment.

## Benchmark coverage

Checks map to controls in the **CIS Microsoft Azure Foundations Benchmark v6.0.0**, across its nine sections: Identity & Access Management, Microsoft Defender for Cloud, Storage Accounts, Database Services, Logging & Monitoring, Networking, Virtual Machines, Key Vault, and AppService.

Control IDs in the report follow v6.0.0 numbering (e.g. Defender plans at `2.1.x`, SQL at `4.1.x`). Some IDs use `.x` to denote a section-level or Manual control where no single automated check maps one-to-one. Checks prefixed **`EXT-`** are extended checks that provide security value but have no direct CIS control (e.g. Azure Firewall presence, AKS RBAC, resource locks) — these are clearly distinguished in the report. See [CIS_v6_MAPPING.md](CIS_v6_MAPPING.md) for the full control mapping.

> This tool maps to CIS controls but is not a certified CIS assessment and does not replace the official [CIS-CAT](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro) tooling.

## Features

- **57 checks across 14 domains** — identity, Defender for Cloud, storage, SQL, logging, networking, VMs, Key Vault, App Service, governance, Entra ID, disks/snapshots, PaaS data services, and containers.
- **Evidence capture** — every `az` command is logged with its command line, UTC timestamp, exit code, and full untruncated output, written to a standalone artifact file for the report appendix.
- **Dual output** — a self-contained dark-themed HTML report with filterable findings and expandable evidence panels, plus a machine-readable JSON file suitable for diffing between assessments or ingesting into a SIEM.
- **CIS-aligned** — findings reference their CIS control ID and link to the relevant Microsoft documentation.
- **Severity-rated findings** — Critical / High / Medium / Low / Info, with a per-domain summary and overall pass rate.

## Requirements

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az`)
- [`jq`](https://jqlang.github.io/jq/)
- `python3` (used for HTML generation; ships with most Linux/macOS systems)

The script checks for all three at startup and exits cleanly if any are missing.

### Permissions

Minimum recommended role assignments on the target subscription:

- **Reader** or **Global Reader** — resource enumeration
- **Security Reader** — Defender for Cloud plans and Secure Score

A subset of Entra ID checks query Microsoft Graph via `az rest`; the authenticated account needs directory read permission for those to return data rather than falling back to a manual-review finding.

## Installation

```bash
git clone https://github.com/Mr-Whiskerss/azure-cis-assessment.git
cd azure-cis-assessment
chmod +x azure_cis_assessment.sh
```

## Usage

Authenticate to the subscription you want to assess, then run the script.

```bash
# Interactive login
az login
az account set --subscription "<subscription-id>"

# Or with a service principal
az login --service-principal -u <appId> -p <secret> --tenant <tenantId>

# Run the assessment
./azure_cis_assessment.sh
```

Output is written to a timestamped directory:

```
azure_assessment_YYYYMMDD_HHMMSS/
├── assessment_report.html      # interactive HTML report
├── assessment_results.json     # structured findings + embedded evidence
├── assessment.log              # full console log
└── evidence/                   # one plaintext artifact per command run
    ├── 0001_az.txt
    ├── 0002_az.txt
    └── ...
```

Open `assessment_report.html` in any browser. The findings table can be filtered by status (Pass / Fail / Warn / Manual), and each finding has an expandable panel showing the exact commands and output behind it.

## Checks by domain

| Domain | Checks | Examples |
|---|---|---|
| Identity & Access | 5 | Conditional Access, guest users, Global Admin count, service principal Owner roles, permanent privileged assignments |
| Defender for Cloud | 9 | Per-workload plan tiers, Secure Score |
| Storage | 4 | HTTPS-only, public blob access, minimum TLS, blob soft delete |
| SQL | 3 | Auditing, firewall rules, Entra ID admin |
| Logging & Monitoring | 4 | Activity log retention, Log Analytics, activity alerts, diagnostic settings |
| Networking | 4 | RDP/SSH exposed to the internet, DDoS protection, Azure Firewall |
| Virtual Machines | 2 | Disk encryption, managed identities |
| Key Vault | 4 | Soft delete, purge protection, RBAC authorization, key/secret expiry |
| App Service | 6 | HTTPS-only, remote debugging, managed identity, minimum TLS, FTP state, HTTP/2 |
| Governance | 3 | Azure Policy assignments, resource locks, management groups |
| Entra ID (advanced) | 4 | App registration secrets, user app registration, user consent, custom roles |
| Disks & Snapshots | 3 | Unattached disks, encryption type, snapshot exposure |
| PaaS Data | 3 | Cosmos DB network access, Redis non-SSL port, PostgreSQL SSL |
| Containers | 3 | AKS RBAC, AKS private cluster, ACR admin user |

## Output formats

### JSON

```json
{
  "report": {
    "title": "Azure CIS Benchmark Assessment",
    "generated": "2026-06-06T07:53:47Z",
    "subscription": { "name": "...", "id": "...", "tenantId": "..." },
    "evidence": { "directory": "evidence/", "artifacts_captured": 52 },
    "summary": { "total": 57, "pass": 14, "fail": 24, "warn": 15, "manual": 4, "error": 0 },
    "findings": [
      {
        "cis_id": "6.1",
        "domain": "Networking",
        "title": "RDP Open to Internet",
        "status": "FAIL",
        "severity": "Critical",
        "detail": "...",
        "recommendation": "...",
        "reference": "CIS 6.1 | https://...",
        "affected_systems": "NSG:nsg-web(RG:rg-prod)",
        "evidence": [
          {
            "command": "az network nsg list -o json",
            "timestamp": "2026-06-06T07:53:44Z",
            "exit_code": 0,
            "artifact": "0023_az.txt"
          }
        ]
      }
    ]
  }
}
```

### HTML

A standalone file (no external dependencies beyond a web font) with a summary dashboard, per-domain breakdown, status filters, and per-finding evidence panels.

## A note on evidence handling

Evidence artifacts contain raw `az` output, which can include resource IDs, IP addresses, principal names, and tenant identifiers. Treat the `evidence/` directory as sensitive and redact it as appropriate before sharing a report outside the engagement.

## Status meanings

| Status | Meaning |
|---|---|
| PASS | The control is correctly configured |
| FAIL | The control is misconfigured or absent |
| WARN | Potential issue or hardening opportunity; review needed |
| MANUAL | Could not be fully determined via CLI; verify manually |
| ERROR | The check could not run (often a permissions issue) |

A `MANUAL` or `ERROR` result is not a pass — it means the tool could not make the determination on its own and a human needs to confirm it.

## Limitations

- The tool assesses what the authenticated identity can see. Findings are only as complete as the granted permissions.
- A `PASS` reflects the configuration state at scan time only.
- Designed for single-subscription assessments; run once per subscription for multi-subscription tenants.

## Contributing

Issues and pull requests are welcome — particularly additional checks, new CIS control coverage, and output format improvements.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorised security assessments only. Only run it against environments you own or have explicit written permission to test.
