#!/usr/bin/env bash
# =============================================================================
# Azure CIS Benchmark Assessment Script
# Author: URM Consulting - Penetration Testing
# Version: 2.0
# Description: Azure CIS Foundations Benchmark v6.0.0 assessment with HTML/JSON output
# =============================================================================

set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
PURPLE='\033[0;35m'

# ─── Config ───────────────────────────────────────────────────────────────────
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="azure_assessment_${TIMESTAMP}"
JSON_FILE="${OUTPUT_DIR}/assessment_results.json"
HTML_FILE="${OUTPUT_DIR}/assessment_report.html"
LOG_FILE="${OUTPUT_DIR}/assessment.log"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Counters ─────────────────────────────────────────────────────────────────
TOTAL=0; PASS=0; FAIL=0; WARN=0; MANUAL=0; ERROR=0

# ─── Findings array (JSON accumulation) ───────────────────────────────────────
FINDINGS="[]"

# ─── Evidence state (file-based; subshell-safe — see az_query) ────────────────
EVIDENCE_SEQ_FILE=""   # set in main once OUTPUT_DIR exists
EVIDENCE_BUF_FILE=""   # per-check buffer of captured commands (JSON-lines)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOG_FILE"; }
pass() { echo -e "${GREEN}[PASS]${RESET} $*" | tee -a "$LOG_FILE"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"; }
info() { echo -e "${BOLD}[INFO]${RESET} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$LOG_FILE"; }

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     Azure CIS Foundations Benchmark v6.0.0 — Tool v2.0          ║"
    echo "║                   URM Consulting                                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

check_deps() {
    log "Checking dependencies..."
    local missing=()
    for cmd in az jq python3; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required tools: ${missing[*]}"
        err "Install: az (Azure CLI), jq, python3"
        exit 1
    fi
    pass "All dependencies satisfied"
}

az_query() {
    # Safe az wrapper — captures evidence for every call, returns stdout.
    # On failure returns empty string (preserving original behaviour under set -e).
    #
    # NOTE: az_query is almost always invoked inside $(...) command substitution,
    # which runs in a subshell. Shell variable mutations would be lost, so the
    # evidence counter and per-check buffer are kept in files (EVIDENCE_SEQ_FILE,
    # EVIDENCE_BUF_FILE) which persist across subshells.
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Atomically increment the on-disk sequence counter
    local seq=1
    if [[ -n "${EVIDENCE_SEQ_FILE:-}" && -f "${EVIDENCE_SEQ_FILE}" ]]; then
        seq=$(( $(cat "$EVIDENCE_SEQ_FILE" 2>/dev/null || echo 0) + 1 ))
        echo "$seq" > "$EVIDENCE_SEQ_FILE"
    fi

    local stdout_file stderr_file exit_code=0
    stdout_file=$(mktemp); stderr_file=$(mktemp)
    az "$@" >"$stdout_file" 2>"$stderr_file" || exit_code=$?

    local out err
    out=$(cat "$stdout_file"); err=$(cat "$stderr_file")
    rm -f "$stdout_file" "$stderr_file"

    [[ -n "$err" ]] && echo "$err" >> "$LOG_FILE"

    if [[ -n "${EVIDENCE_DIR:-}" && -d "${EVIDENCE_DIR:-/nonexistent}" ]]; then
        local artifact
        artifact="${EVIDENCE_DIR}/$(printf '%04d' "$seq")_az.txt"
        {
            echo "=============================================================="
            echo "EVIDENCE #${seq}"
            echo "Timestamp  : $ts"
            echo "Command    : az $*"
            echo "Exit code  : $exit_code"
            echo "=============================================================="
            echo "--- STDOUT ---"
            echo "$out"
            if [[ -n "$err" ]]; then
                echo "--- STDERR ---"
                echo "$err"
            fi
        } > "$artifact"

        # Append a structured evidence record (one JSON object per line) to the
        # per-check buffer file. add_finding reads and clears this file.
        if [[ -n "${EVIDENCE_BUF_FILE:-}" ]]; then
            jq -n -c \
                --arg seq "$seq" \
                --arg cmd "az $*" \
                --arg ts "$ts" \
                --arg code "$exit_code" \
                --arg out "$(echo "$out" | head -c 4000)" \
                --arg err "$(echo "$err" | head -c 1000)" \
                --arg file "$(basename "$artifact")" \
                '{seq: ($seq|tonumber), command: $cmd, timestamp: $ts, exit_code: ($code|tonumber), output: $out, stderr: $err, artifact: $file}' \
                >> "$EVIDENCE_BUF_FILE" 2>/dev/null || true
        fi
    fi

    echo "$out"
}

# ─── Numeric sanitiser ─────────────────────────────────────────────────────────
# Guarantees a clean integer from any az/jq output. Non-numeric -> 0.
num() {
    local v="${1:-0}"
    v="${v//[$'\t\r\n ']/}"          # strip whitespace
    if [[ "$v" =~ ^-?[0-9]+$ ]]; then
        echo "$v"
    else
        echo "0"
    fi
}

# ─── Evidence capture ──────────────────────────────────────────────────────────
# Evidence is captured automatically by az_query for every Azure command run
# during a check. Because az_query usually runs inside $(...) subshells, the
# sequence counter and per-check buffer live in files (set up in main).
# add_finding() reads the buffer, attaches it to the finding, and clears it.

evidence_reset() {
    : > "${EVIDENCE_BUF_FILE:-/dev/null}"
}

# ─── Add finding to JSON ───────────────────────────────────────────────────────
add_finding() {
    local cis_id="$1"
    local domain="$2"
    local title="$3"
    local status="$4"   # PASS | FAIL | WARN | MANUAL | ERROR
    local severity="$5" # Critical | High | Medium | Low | Info
    local detail="$6"
    local recommendation="${7:-}"
    local reference="${8:-}"
    local affected="${9:-}"   # optional: comma/semicolon separated affected resources

    TOTAL=$((TOTAL + 1))
    case "$status" in
        PASS)   PASS=$((PASS + 1)) ;;
        FAIL)   FAIL=$((FAIL + 1)) ;;
        WARN)   WARN=$((WARN + 1)) ;;
        MANUAL) MANUAL=$((MANUAL + 1)) ;;
        ERROR)  ERROR=$((ERROR + 1)) ;;
    esac

    # Read evidence captured for this check from the buffer file (JSON-lines),
    # assemble into an array, then clear the buffer for the next check.
    local evidence_json="[]"
    if [[ -n "${EVIDENCE_BUF_FILE:-}" && -s "${EVIDENCE_BUF_FILE}" ]]; then
        evidence_json=$(jq -s '.' "$EVIDENCE_BUF_FILE" 2>/dev/null || echo "[]")
    fi

    # Build the finding object with jq so all strings are safely encoded,
    # and attach the evidence captured for this check.
    local entry
    entry=$(jq -n \
        --arg cis_id "$cis_id" \
        --arg domain "$domain" \
        --arg title "$title" \
        --arg status "$status" \
        --arg severity "$severity" \
        --arg detail "$detail" \
        --arg recommendation "$recommendation" \
        --arg reference "$reference" \
        --arg affected "$affected" \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson evidence "$evidence_json" \
        '{cis_id: $cis_id, domain: $domain, title: $title, status: $status, severity: $severity, detail: $detail, recommendation: $recommendation, reference: $reference, affected_systems: $affected, timestamp: $timestamp, evidence: $evidence}')

    FINDINGS=$(echo "$FINDINGS" | jq --argjson entry "$entry" '. += [$entry]')

    # Clear the evidence buffer ready for the next check
    : > "${EVIDENCE_BUF_FILE:-/dev/null}"
}

# =============================================================================
# SECTION 1: IDENTITY & ACCESS MANAGEMENT
# =============================================================================

assess_iam() {
    echo -e "\n${BOLD}━━━ Section 1: Identity & Access Management ━━━${RESET}"

    # 1.1 — Security defaults or Conditional Access
    log "1.1 Checking security defaults / Conditional Access policies..."
    local ca_policies
    ca_policies=$(az_query rest --method GET \
        --url "https://graph.microsoft.com/v1.0/identity/conditionalAccessPolicies" \
        --query "value[?state=='enabled'] | length(@)" -o tsv 2>/dev/null || echo "0")

    if [[ "$ca_policies" -gt 0 ]] 2>/dev/null; then
        pass "1.1 Conditional Access policies found: $ca_policies enabled"
        add_finding "1.1" "IAM" "Conditional Access Policies Enabled" "PASS" "Info" \
            "$ca_policies Conditional Access policies are enabled." \
            "" "https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/"
    else
        fail "1.1 No Conditional Access policies detected — verify Security Defaults"
        add_finding "1.1" "IAM" "Conditional Access / Security Defaults" "MANUAL" "High" \
            "Could not enumerate Conditional Access policies via CLI. Verify Security Defaults or CA policies are enabled in Entra ID portal." \
            "Enable Conditional Access policies or Security Defaults. Require MFA for all users." \
            "CIS 1.1 | https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults"
    fi

    # 1.2 — Guest user permissions
    log "1.2 Checking guest users..."
    local guests
    guests=$(az_query ad user list --filter "userType eq 'Guest'" --query "length(@)" -o tsv 2>/dev/null || echo "unknown")
    if [[ "$guests" == "0" ]]; then
        pass "1.2 No guest users found"
        add_finding "1.5" "IAM" "Guest User Presence" "PASS" "Low" "No guest users present in tenant." "" "CIS 1.5"
    elif [[ "$guests" == "unknown" ]]; then
        warn "1.2 Could not enumerate guest users"
        add_finding "1.5" "IAM" "Guest User Presence" "ERROR" "Medium" "Failed to enumerate guest users." \
            "Manually review Entra ID > Users > Filter by Guest" "CIS 1.5"
    else
        warn "1.2 $guests guest user(s) found — review access"
        add_finding "1.5" "IAM" "Guest User Presence" "WARN" "Medium" \
            "$guests guest user(s) found. Review whether access is appropriate and time-limited." \
            "Review guest user access. Restrict guest permissions via External Collaboration Settings." \
            "CIS 1.5 | https://learn.microsoft.com/en-us/azure/active-directory/external-identities/"
    fi

    # 1.3 — Global Administrators count
    log "1.3 Checking Global Administrator count..."
    local ga_role_id
    ga_role_id=$(az_query rest --method GET \
        --url "https://graph.microsoft.com/v1.0/directoryRoles" \
        --query "value[?displayName=='Global Administrator'].id | [0]" -o tsv 2>/dev/null || echo "")

    local ga_count=0
    if [[ -n "$ga_role_id" ]]; then
        ga_count=$(az_query rest --method GET \
            --url "https://graph.microsoft.com/v1.0/directoryRoles/${ga_role_id}/members" \
            --query "value | length(@)" -o tsv 2>/dev/null || echo "0")
    fi

    if [[ "$ga_count" -le 4 && "$ga_count" -ge 2 ]] 2>/dev/null; then
        pass "1.3 Global Administrator count is $ga_count (within recommended 2-4 range)"
        add_finding "1.3" "IAM" "Global Administrator Count" "PASS" "Info" \
            "$ga_count Global Administrators found. CIS recommends between 2 and 4." "" "CIS 1.3"
    elif [[ "$ga_count" -gt 4 ]] 2>/dev/null; then
        fail "1.3 Excessive Global Administrators: $ga_count (CIS recommends 2-4)"
        add_finding "1.3" "IAM" "Global Administrator Count" "FAIL" "High" \
            "$ga_count Global Administrators found. This exceeds the CIS recommended maximum of 4 and increases the blast radius of a compromised account." \
            "Reduce Global Administrators to 2-4. Use PIM for eligible assignment rather than permanent. Assign least-privilege roles." \
            "CIS 1.3 | https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices"
    else
        warn "1.3 Could not determine GA count or count is below 2"
        add_finding "1.3" "IAM" "Global Administrator Count" "WARN" "Medium" \
            "GA count: $ga_count. CIS recommends at least 2 for redundancy." \
            "Ensure at least 2 Global Administrators exist for break-glass scenarios." "CIS 1.3"
    fi

    # 1.4 — No subscription-level Owner service principals
    log "1.4 Checking for service principals with Owner role..."
    local sp_owners
    sp_owners=$(az_query role assignment list --all \
        --query "[?roleDefinitionName=='Owner' && principalType=='ServicePrincipal'].principalName" \
        -o tsv 2>/dev/null || echo "")

    if [[ -z "$sp_owners" ]]; then
        pass "1.4 No service principals with Owner role found"
        add_finding "1.23" "IAM" "Service Principal Owner Assignments" "PASS" "Info" \
            "No service principals hold the Owner role at subscription level." "" "CIS 1.23"
    else
        local count
        count=$(echo "$sp_owners" | grep -c . || true)
        fail "1.4 $count service principal(s) with Owner role: $sp_owners"
        add_finding "1.23" "IAM" "Service Principal Owner Assignments" "FAIL" "Critical" \
            "$count service principal(s) found with Owner rights: $sp_owners — exploitation of these SPs yields full subscription control." \
            "Replace Owner with the minimum required role. Use Contributor or custom roles. Audit SP credentials and rotation policy." \
            "CIS 1.23 | https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices" \
            "$(echo "$sp_owners" | tr '\n' ',' | sed 's/,/, /g; s/, *$//; s/^ *//')"
    fi

    # 1.5 — Users with permanent privileged roles (PIM check)
    log "1.5 Checking for non-PIM privileged role assignments..."
    local permanent_privs
    permanent_privs=$(az_query role assignment list --all \
        --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='User Access Administrator'].{Name:principalName,Role:roleDefinitionName,Type:principalType}" \
        -o json 2>/dev/null || echo "[]")

    local priv_count
    priv_count=$(echo "$permanent_privs" | jq 'length' 2>/dev/null || echo "0")

    if [[ "$priv_count" -eq 0 ]]; then
        pass "1.5 No permanent Owner/Contributor/UAA assignments found"
        add_finding "1.1.x" "IAM" "Permanent Privileged Role Assignments" "PASS" "Info" \
            "No permanent high-privilege role assignments detected." "" "CIS 1.1.x"
    else
        warn "1.5 $priv_count permanent privileged role assignment(s) found"
        local summary
        summary=$(echo "$permanent_privs" | jq -r '.[] | "\(.Type): \(.Name) — \(.Role)"' | head -20 | tr '\n' '; ')
        add_finding "1.1.x" "IAM" "Permanent Privileged Role Assignments" "WARN" "High" \
            "$priv_count permanent high-privilege assignments: $summary" \
            "Use Azure PIM for eligible (time-bound, approval-based) role assignments. Remove standing access for privileged roles." \
            "CIS 1.1.x | https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/"
    fi
}

# =============================================================================
# SECTION 2: MICROSOFT DEFENDER FOR CLOUD
# =============================================================================

assess_defender() {
    echo -e "\n${BOLD}━━━ Section 2: Microsoft Defender for Cloud ━━━${RESET}"

    log "2.1 Checking Defender for Cloud pricing tiers..."
    local pricing
    pricing=$(az_query security pricing list -o json 2>/dev/null || echo "[]")

    local plans=("VirtualMachines" "SqlServers" "AppServices" "StorageAccounts" "Containers" "KeyVaults" "Dns" "Arm")

    # CIS v6.0.0 control IDs per Defender plan
    declare -A plan_cis=(
        ["VirtualMachines"]="2.1.1"
        ["AppServices"]="2.1.2"
        ["SqlServers"]="2.1.4"
        ["StorageAccounts"]="2.1.5"
        ["Containers"]="2.1.7"
        ["KeyVaults"]="2.1.10"
        ["Arm"]="2.1.12"
        ["Dns"]="2.1.13"
    )

    for plan in "${plans[@]}"; do
        local cis_ref="${plan_cis[$plan]:-2.1.x}"
        local tier
        tier=$(echo "$pricing" | jq -r --arg p "$plan" '.[] | select(.name==$p) | .pricingTier' 2>/dev/null || echo "unknown")
        if [[ "$tier" == "Standard" ]]; then
            pass "${cis_ref} Defender for $plan: Standard (enabled)"
            add_finding "${cis_ref}" "Defender" "Defender for $plan" "PASS" "Info" \
                "Defender for $plan is enabled (Standard tier)." "" "CIS ${cis_ref}"
        elif [[ "$tier" == "Free" ]]; then
            fail "${cis_ref} Defender for $plan: Free tier (disabled)"
            add_finding "${cis_ref}" "Defender" "Defender for $plan" "FAIL" "High" \
                "Defender for $plan is on Free tier — no threat detection active for this workload." \
                "Upgrade to Standard tier. Review cost implications and enable at minimum for internet-facing or data workloads." \
                "CIS ${cis_ref} | https://learn.microsoft.com/en-us/azure/defender-for-cloud/"
        else
            warn "${cis_ref} Defender for $plan: Unknown/error ($tier)"
            add_finding "${cis_ref}" "Defender" "Defender for $plan" "ERROR" "Medium" \
                "Could not determine Defender plan status for $plan." \
                "Verify via Azure Portal > Defender for Cloud > Environment Settings." "CIS ${cis_ref}"
        fi
    done

    # 2.2 — Secure Score
    log "2.2 Checking Secure Score..."
    local score
    score=$(az_query security secure-score list --query "[0].{Score:properties.score.current,Max:properties.score.max,Pct:properties.score.percentage}" -o json 2>/dev/null || echo "{}")
    local pct
    pct=$(echo "$score" | jq -r '.Pct // "unknown"' 2>/dev/null || echo "unknown")

    if [[ "$pct" != "unknown" ]]; then
        local pct_int
        pct_int=$(echo "$pct" | awk '{printf "%.0f", $1*100}')
        if [[ "$pct_int" -ge 70 ]]; then
            pass "2.2 Secure Score: ${pct_int}% — Acceptable"
            add_finding "2.2" "Defender" "Secure Score" "PASS" "Info" "Secure Score is ${pct_int}%." "" "CIS 2.1"
        elif [[ "$pct_int" -ge 50 ]]; then
            warn "2.2 Secure Score: ${pct_int}% — Below recommended 70%"
            add_finding "2.2" "Defender" "Secure Score" "WARN" "Medium" "Secure Score is ${pct_int}%. Recommended minimum is 70%." \
                "Review and remediate Defender for Cloud recommendations, prioritising High severity items." "CIS 2.1"
        else
            fail "2.2 Secure Score: ${pct_int}% — Critical"
            add_finding "2.2" "Defender" "Secure Score" "FAIL" "High" "Secure Score is critically low at ${pct_int}%." \
                "Immediately review Defender for Cloud recommendations. Focus on Critical and High severity findings." "CIS 2.1"
        fi
    else
        add_finding "2.2" "Defender" "Secure Score" "ERROR" "Info" \
            "Could not retrieve Secure Score." "Check permissions — requires Security Reader." "CIS 2.1"
    fi
}

# =============================================================================
# SECTION 3: STORAGE ACCOUNTS
# =============================================================================

assess_storage() {
    echo -e "\n${BOLD}━━━ Section 3: Storage Accounts ━━━${RESET}"

    log "3.x Enumerating storage accounts..."
    local accounts
    accounts=$(az_query storage account list -o json 2>/dev/null || echo "[]")
    local count
    count=$(echo "$accounts" | jq 'length' 2>/dev/null || echo "0")
    log "Found $count storage account(s)"

    # 3.1 — HTTPS only
    local http_only
    http_only=$(echo "$accounts" | jq '[.[] | select(.enableHttpsTrafficOnly==false)] | length' 2>/dev/null || echo "0")
    if [[ "$http_only" -eq 0 ]]; then
        pass "3.1 All storage accounts enforce HTTPS"
        add_finding "3.1" "Storage" "Storage HTTPS Only" "PASS" "Info" \
            "All $count storage accounts have enableHttpsTrafficOnly=true." "" "CIS 3.1"
    else
        fail "3.1 $http_only storage account(s) allow HTTP traffic"
        local names
        names=$(echo "$accounts" | jq -r '[.[] | select(.enableHttpsTrafficOnly==false) | .name] | join(", ")' 2>/dev/null)
        add_finding "3.1" "Storage" "Storage HTTPS Only" "FAIL" "High" \
            "$http_only account(s) allow unencrypted HTTP: $names" \
            "Set 'Secure transfer required' to Enabled on all storage accounts." \
            "CIS 3.1 | https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer" \
            "$names"
    fi

    # 3.2 — Public blob access
    local public_blob
    public_blob=$(echo "$accounts" | jq '[.[] | select(.allowBlobPublicAccess==true)] | length' 2>/dev/null || echo "0")
    if [[ "$public_blob" -eq 0 ]]; then
        pass "3.2 No storage accounts with public blob access"
        add_finding "3.7" "Storage" "Public Blob Access" "PASS" "Info" \
            "No storage accounts allow public blob access." "" "CIS 3.7"
    else
        fail "3.2 $public_blob storage account(s) allow public blob access"
        local pub_names
        pub_names=$(echo "$accounts" | jq -r '[.[] | select(.allowBlobPublicAccess==true) | .name] | join(", ")' 2>/dev/null)
        add_finding "3.7" "Storage" "Public Blob Access" "FAIL" "Critical" \
            "$public_blob account(s) allow public blob access: $pub_names — unauthenticated data exposure risk." \
            "Disable public blob access unless explicitly required. Audit existing public containers for sensitive data." \
            "CIS 3.7 | https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent" \
            "$pub_names"
    fi

    # 3.3 — Minimum TLS version
    local old_tls
    old_tls=$(echo "$accounts" | jq '[.[] | select(.minimumTlsVersion!="TLS1_2")] | length' 2>/dev/null || echo "0")
    if [[ "$old_tls" -eq 0 ]]; then
        pass "3.3 All storage accounts require TLS 1.2"
        add_finding "3.12" "Storage" "Storage Minimum TLS Version" "PASS" "Info" \
            "All storage accounts enforce TLS 1.2." "" "CIS 3.12"
    else
        fail "3.3 $old_tls storage account(s) allow TLS below 1.2"
        add_finding "3.12" "Storage" "Storage Minimum TLS Version" "FAIL" "High" \
            "$old_tls account(s) do not enforce TLS 1.2 minimum — vulnerable to downgrade attacks." \
            "Set minimumTlsVersion to TLS1_2 on all storage accounts." \
            "CIS 3.12 | https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version"
    fi

    # 3.4 — Soft delete for blobs
    log "3.4 Checking blob soft delete..."
    local no_softdelete=0
    while IFS= read -r account_json; do
        local name rg
        name=$(echo "$account_json" | jq -r '.name')
        rg=$(echo "$account_json" | jq -r '.resourceGroup')
        local blob_props
        blob_props=$(az_query storage blob service-properties delete-policy show \
            --account-name "$name" --resource-group "$rg" -o json 2>/dev/null || echo '{"enabled":false}')
        local enabled
        enabled=$(echo "$blob_props" | jq -r '.enabled' 2>/dev/null || echo "false")
        if [[ "$enabled" != "true" ]]; then
            no_softdelete=$((no_softdelete + 1))
        fi
    done < <(echo "$accounts" | jq -c '.[]' 2>/dev/null)

    if [[ "$no_softdelete" -eq 0 ]]; then
        pass "3.4 Blob soft delete enabled on all storage accounts"
        add_finding "3.11" "Storage" "Blob Soft Delete" "PASS" "Info" \
            "Blob soft delete is enabled across all storage accounts." "" "CIS 3.11"
    else
        fail "3.4 $no_softdelete storage account(s) missing blob soft delete"
        add_finding "3.11" "Storage" "Blob Soft Delete" "FAIL" "Medium" \
            "$no_softdelete account(s) do not have blob soft delete enabled — accidental/malicious deletion is unrecoverable." \
            "Enable blob soft delete with at least 7 day retention on all storage accounts." \
            "CIS 3.11 | https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview"
    fi
}

# =============================================================================
# SECTION 4: SQL / DATABASE
# =============================================================================

assess_sql() {
    echo -e "\n${BOLD}━━━ Section 4: SQL Databases ━━━${RESET}"

    log "4.x Enumerating SQL servers..."
    local servers
    servers=$(az_query sql server list -o json 2>/dev/null || echo "[]")
    local count
    count=$(echo "$servers" | jq 'length' 2>/dev/null || echo "0")
    log "Found $count SQL server(s)"

    if [[ "$count" -eq 0 ]]; then
        info "4.x No SQL servers found — skipping SQL checks"
        add_finding "4.0" "SQL" "SQL Server Presence" "PASS" "Info" "No Azure SQL servers found in scope." "" "CIS 4.x"
        return
    fi

    while IFS= read -r server_json; do
        local srv_name srv_rg
        srv_name=$(echo "$server_json" | jq -r '.name')
        srv_rg=$(echo "$server_json" | jq -r '.resourceGroup')

        # 4.1 — Auditing
        local audit
        audit=$(az_query sql server audit-policy show \
            --resource-group "$srv_rg" --name "$srv_name" \
            --query "state" -o tsv 2>/dev/null || echo "Unknown")
        if [[ "$audit" == "Enabled" ]]; then
            pass "4.1 [$srv_name] SQL Auditing enabled"
            add_finding "4.1.1.${srv_name}" "SQL" "SQL Auditing: $srv_name" "PASS" "Info" \
                "SQL auditing is enabled on $srv_name." "" "CIS 4.1.1"
        else
            fail "4.1 [$srv_name] SQL Auditing DISABLED"
            add_finding "4.1.1.${srv_name}" "SQL" "SQL Auditing: $srv_name" "FAIL" "High" \
                "SQL auditing is disabled on $srv_name — no audit trail for database access/changes." \
                "Enable SQL auditing and configure logs to ship to Log Analytics or Storage Account with 90+ day retention." \
                "CIS 4.1.1 | https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview"
        fi

        # 4.2 — Firewall rules (look for 0.0.0.0 - 255.255.255.255)
        local fw_rules
        fw_rules=$(az_query sql server firewall-rule list \
            --resource-group "$srv_rg" --server "$srv_name" -o json 2>/dev/null || echo "[]")
        local open_fw
        open_fw=$(echo "$fw_rules" | jq '[.[] | select(.startIpAddress=="0.0.0.0" and .endIpAddress=="255.255.255.255")] | length' 2>/dev/null || echo "0")
        if [[ "$open_fw" -eq 0 ]]; then
            pass "4.2 [$srv_name] No unrestricted SQL firewall rules"
            add_finding "4.1.2.${srv_name}" "SQL" "SQL Firewall Rules: $srv_name" "PASS" "Info" \
                "No wildcard (0.0.0.0-255.255.255.255) firewall rules on $srv_name." "" "CIS 4.1.2"
        else
            fail "4.2 [$srv_name] Unrestricted firewall rule detected"
            add_finding "4.1.2.${srv_name}" "SQL" "SQL Firewall Rules: $srv_name" "FAIL" "Critical" \
                "Wildcard firewall rule (0.0.0.0-255.255.255.255) found on $srv_name — database is internet-accessible." \
                "Remove wildcard rules. Restrict access to specific known IP ranges or use Private Endpoints." \
                "CIS 4.1.2 | https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"
        fi

        # 4.3 — Azure AD admin
        local ad_admin
        ad_admin=$(az_query sql server ad-admin list \
            --resource-group "$srv_rg" --server "$srv_name" \
            --query "length(@)" -o tsv 2>/dev/null || echo "0")
        if [[ "$ad_admin" -gt 0 ]] 2>/dev/null; then
            pass "4.3 [$srv_name] Azure AD admin configured"
            add_finding "4.1.5.${srv_name}" "SQL" "SQL AAD Admin: $srv_name" "PASS" "Info" \
                "Azure AD admin is configured on $srv_name." "" "CIS 4.1.5"
        else
            fail "4.3 [$srv_name] No Azure AD admin configured"
            add_finding "4.1.5.${srv_name}" "SQL" "SQL AAD Admin: $srv_name" "FAIL" "Medium" \
                "No Azure AD administrator configured on $srv_name — SQL-only authentication may allow credential-based attacks." \
                "Configure an Azure AD administrator for SQL server. Disable SQL authentication where possible." \
                "CIS 4.1.5 | https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure"
        fi

    done < <(echo "$servers" | jq -c '.[]' 2>/dev/null)
}

# =============================================================================
# SECTION 5: LOGGING & MONITORING
# =============================================================================

assess_logging() {
    echo -e "\n${BOLD}━━━ Section 5: Logging & Monitoring ━━━${RESET}"

    # 5.1 — Activity log retention
    log "5.1 Checking activity log retention..."
    local log_profiles
    log_profiles=$(az_query monitor log-profiles list -o json 2>/dev/null || echo "[]")
    local retention
    retention=$(echo "$log_profiles" | jq -r '.[0].retentionPolicy.days // "0"' 2>/dev/null || echo "0")

    if [[ "$retention" -ge 365 ]] 2>/dev/null; then
        pass "5.1 Activity log retention: $retention days"
        add_finding "5.1" "Logging" "Activity Log Retention" "PASS" "Info" \
            "Activity log retention is set to $retention days (CIS requires >= 365)." "" "CIS 5.1"
    elif [[ "$retention" -eq 0 ]] 2>/dev/null; then
        warn "5.1 Could not determine retention or no log profile configured"
        add_finding "5.1" "Logging" "Activity Log Retention" "WARN" "Medium" \
            "No log profile configured or retention is 0. Activity logs may not be retained." \
            "Configure a diagnostic setting or log profile with 365+ day retention." "CIS 5.1"
    else
        fail "5.1 Activity log retention only $retention days (minimum 365 required)"
        add_finding "5.1" "Logging" "Activity Log Retention" "FAIL" "Medium" \
            "Activity log retention is $retention days — insufficient for incident response and forensics (CIS requires 365+)." \
            "Update log profile retention policy to a minimum of 365 days." \
            "CIS 5.1 | https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"
    fi

    # 5.2 — Log Analytics workspace
    log "5.2 Checking Log Analytics workspaces..."
    local workspaces
    workspaces=$(az_query monitor log-analytics workspace list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$workspaces" -gt 0 ]] 2>/dev/null; then
        pass "5.2 $workspaces Log Analytics workspace(s) found"
        add_finding "5.2" "Logging" "Log Analytics Workspace" "PASS" "Info" \
            "$workspaces Log Analytics workspace(s) configured." "" "CIS 5.1.x"
    else
        fail "5.2 No Log Analytics workspaces found"
        add_finding "5.2" "Logging" "Log Analytics Workspace" "FAIL" "High" \
            "No Log Analytics workspaces found — centralised logging and alerting is unavailable." \
            "Create a Log Analytics workspace and connect all Azure resources and Defender for Cloud to it." \
            "CIS 5.x | https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview"
    fi

    # 5.3 — Activity log alerts
    log "5.3 Checking activity log alerts..."
    local alerts
    alerts=$(az_query monitor activity-log alert list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$alerts" -gt 0 ]] 2>/dev/null; then
        pass "5.3 $alerts activity log alert(s) configured"
        add_finding "5.3" "Logging" "Activity Log Alerts" "PASS" "Info" \
            "$alerts activity log alerts are configured." "" "CIS 5.2"
    else
        fail "5.3 No activity log alerts configured"
        add_finding "5.3" "Logging" "Activity Log Alerts" "FAIL" "High" \
            "No activity log alerts found — critical operations (policy changes, NSG changes, etc.) are unmonitored." \
            "Configure alerts for: Policy changes, NSG changes, Security policy changes, Key Vault access, Firewall changes." \
            "CIS 5.2 | https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts"
    fi

    # 5.4 — Diagnostic settings on subscription
    log "5.4 Checking subscription diagnostic settings..."
    local sub_id
    sub_id=$(az_query account show --query "id" -o tsv 2>/dev/null || echo "")
    local diag_count=0
    if [[ -n "$sub_id" ]]; then
        diag_count=$(az_query monitor diagnostic-settings list \
            --resource "/subscriptions/${sub_id}" \
            --query "length(@)" -o tsv 2>/dev/null || echo "0")
    fi

    if [[ "$diag_count" -gt 0 ]] 2>/dev/null; then
        pass "5.4 Subscription diagnostic settings configured"
        add_finding "5.4" "Logging" "Subscription Diagnostic Settings" "PASS" "Info" \
            "Subscription-level diagnostic settings are configured." "" "CIS 5.3"
    else
        fail "5.4 No subscription-level diagnostic settings"
        add_finding "5.4" "Logging" "Subscription Diagnostic Settings" "FAIL" "High" \
            "No diagnostic settings configured at subscription level — control plane activity not being forwarded to Log Analytics/SIEM." \
            "Configure subscription diagnostic settings to export all log categories to Log Analytics." "CIS 5.3"
    fi
}

# =============================================================================
# SECTION 6: NETWORKING
# =============================================================================

assess_networking() {
    echo -e "\n${BOLD}━━━ Section 6: Networking ━━━${RESET}"

    log "6.x Enumerating NSGs..."
    local nsgs
    nsgs=$(az_query network nsg list -o json 2>/dev/null || echo "[]")
    local nsg_count
    nsg_count=$(echo "$nsgs" | jq 'length' 2>/dev/null || echo "0")
    log "Found $nsg_count NSG(s)"

    # 6.1 — RDP open to internet
    log "6.1 Checking for RDP (3389) open to internet..."
    local rdp_open=0
    local rdp_details=""

    while IFS= read -r nsg_json; do
        local nsg_name nsg_rg
        nsg_name=$(echo "$nsg_json" | jq -r '.name')
        nsg_rg=$(echo "$nsg_json" | jq -r '.resourceGroup')

        local open_rdp
        open_rdp=$(echo "$nsg_json" | jq '[
            .securityRules[]? |
            select(
                .access=="Allow" and
                .direction=="Inbound" and
                (.destinationPortRange=="3389" or (.destinationPortRanges[]? // "" | contains("3389"))) and
                (.sourceAddressPrefix=="*" or .sourceAddressPrefix=="Internet" or .sourceAddressPrefix=="0.0.0.0/0" or .sourceAddressPrefix=="Any")
            )
        ] | length' 2>/dev/null || echo "0")

        if [[ "$open_rdp" -gt 0 ]]; then
            rdp_open=$((rdp_open + 1))
            rdp_details="$rdp_details NSG:$nsg_name(RG:$nsg_rg);"
        fi
    done < <(echo "$nsgs" | jq -c '.[]' 2>/dev/null)

    if [[ "$rdp_open" -eq 0 ]]; then
        pass "6.1 No NSGs with RDP open to internet"
        add_finding "6.1" "Networking" "RDP Open to Internet" "PASS" "Info" \
            "No NSGs allow inbound RDP (3389) from internet sources." "" "CIS 6.1"
    else
        fail "6.1 $rdp_open NSG(s) allow RDP from internet: $rdp_details"
        add_finding "6.1" "Networking" "RDP Open to Internet" "FAIL" "Critical" \
            "$rdp_open NSG(s) allow inbound RDP (3389) from any internet source: $rdp_details" \
            "Remove internet-facing RDP rules. Use Azure Bastion, Just-in-Time VM Access, or VPN for RDP access." \
            "CIS 6.1 | https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices" \
            "$(echo "$rdp_details" | sed 's/^[ ;]*//; s/[ ;]*$//; s/; */; /g')"
    fi

    # 6.2 — SSH open to internet
    log "6.2 Checking for SSH (22) open to internet..."
    local ssh_open=0
    local ssh_details=""

    while IFS= read -r nsg_json; do
        local nsg_name
        nsg_name=$(echo "$nsg_json" | jq -r '.name')
        local nsg_rg
        nsg_rg=$(echo "$nsg_json" | jq -r '.resourceGroup')

        local open_ssh
        open_ssh=$(echo "$nsg_json" | jq '[
            .securityRules[]? |
            select(
                .access=="Allow" and
                .direction=="Inbound" and
                (.destinationPortRange=="22" or (.destinationPortRanges[]? // "" | contains("22"))) and
                (.sourceAddressPrefix=="*" or .sourceAddressPrefix=="Internet" or .sourceAddressPrefix=="0.0.0.0/0" or .sourceAddressPrefix=="Any")
            )
        ] | length' 2>/dev/null || echo "0")

        if [[ "$open_ssh" -gt 0 ]]; then
            ssh_open=$((ssh_open + 1))
            ssh_details="$ssh_details NSG:$nsg_name(RG:$nsg_rg);"
        fi
    done < <(echo "$nsgs" | jq -c '.[]' 2>/dev/null)

    if [[ "$ssh_open" -eq 0 ]]; then
        pass "6.2 No NSGs with SSH open to internet"
        add_finding "6.2" "Networking" "SSH Open to Internet" "PASS" "Info" \
            "No NSGs allow inbound SSH (22) from internet sources." "" "CIS 6.2"
    else
        fail "6.2 $ssh_open NSG(s) allow SSH from internet: $ssh_details"
        add_finding "6.2" "Networking" "SSH Open to Internet" "FAIL" "Critical" \
            "$ssh_open NSG(s) allow inbound SSH (22) from any internet source: $ssh_details" \
            "Remove internet-facing SSH rules. Use Azure Bastion or JIT VM Access with IP restrictions." \
            "CIS 6.2 | https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices" \
            "$(echo "$ssh_details" | sed 's/^[ ;]*//; s/[ ;]*$//; s/; */; /g')"
    fi

    # 6.3 — DDoS protection
    log "6.3 Checking DDoS protection..."
    local ddos
    ddos=$(az_query network ddos-protection plan list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$ddos" -gt 0 ]] 2>/dev/null; then
        pass "6.3 DDoS protection plan configured"
        add_finding "6.3" "Networking" "DDoS Protection" "PASS" "Info" \
            "Azure DDoS Protection plan is configured." "" "CIS 6 (Manual)"
    else
        warn "6.3 No DDoS protection plan found"
        add_finding "6.3" "Networking" "DDoS Protection" "WARN" "Medium" \
            "No DDoS Protection plan configured. Internet-facing resources rely only on basic DDoS protection." \
            "Consider Azure DDoS Network Protection for internet-facing applications. Evaluate cost vs risk." \
            "CIS 6.x | https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"
    fi

    # 6.4 — Azure Firewall / WAF presence
    log "6.4 Checking for Azure Firewall..."
    local azfw
    azfw=$(az_query network firewall list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$azfw" -gt 0 ]] 2>/dev/null; then
        pass "6.4 Azure Firewall deployed"
        add_finding "EXT-NET1" "Networking" "Azure Firewall" "PASS" "Info" \
            "$azfw Azure Firewall instance(s) found." "" "CIS 6 (Manual)"
    else
        warn "6.4 No Azure Firewall found"
        add_finding "EXT-NET1" "Networking" "Azure Firewall" "WARN" "Low" \
            "No Azure Firewall detected. Network traffic filtering may rely solely on NSGs." \
            "Evaluate Azure Firewall or third-party NVA for centralised network traffic inspection and filtering." \
            "CIS 6.x | https://learn.microsoft.com/en-us/azure/firewall/overview"
    fi
}

# =============================================================================
# SECTION 7: VIRTUAL MACHINES
# =============================================================================

assess_vms() {
    echo -e "\n${BOLD}━━━ Section 7: Virtual Machines ━━━${RESET}"

    log "7.x Enumerating virtual machines..."
    local vms
    vms=$(az_query vm list -o json 2>/dev/null || echo "[]")
    local vm_count
    vm_count=$(echo "$vms" | jq 'length' 2>/dev/null || echo "0")
    log "Found $vm_count VM(s)"

    if [[ "$vm_count" -eq 0 ]]; then
        info "7.x No VMs found — skipping VM checks"
        add_finding "7.0" "VirtualMachines" "VM Presence" "PASS" "Info" "No virtual machines found in scope." "" "Extended check (no CIS control)"
        return
    fi

    # 7.1 — Disk encryption
    log "7.1 Checking disk encryption..."
    local unencrypted=0
    local unenc_names=""

    while IFS= read -r vm_json; do
        local vm_name vm_rg
        vm_name=$(echo "$vm_json" | jq -r '.name')
        vm_rg=$(echo "$vm_json" | jq -r '.resourceGroup')

        local enc_status
        enc_status=$(az_query vm encryption show \
            --name "$vm_name" --resource-group "$vm_rg" \
            --query "disks[0].statuses[0].code" -o tsv 2>/dev/null || echo "unknown")

        if [[ "$enc_status" != *"EncryptionState/encrypted"* && "$enc_status" != "unknown" ]]; then
            unencrypted=$((unencrypted + 1))
            unenc_names="$unenc_names $vm_name;"
        fi
    done < <(echo "$vms" | jq -c '.[]' 2>/dev/null)

    if [[ "$unencrypted" -eq 0 ]]; then
        pass "7.1 All VMs have disk encryption (or encryption status verified)"
        add_finding "7.1" "VirtualMachines" "VM Disk Encryption" "PASS" "Info" \
            "All checked VMs appear to have disk encryption enabled." "" "CIS 7.3"
    else
        fail "7.1 $unencrypted VM(s) without disk encryption: $unenc_names"
        add_finding "7.1" "VirtualMachines" "VM Disk Encryption" "FAIL" "High" \
            "$unencrypted VM(s) without disk encryption detected: $unenc_names" \
            "Enable Azure Disk Encryption (ADE) or Server-Side Encryption with CMK on all VM disks." \
            "CIS 7.3 | https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview" \
            "$(echo "$unenc_names" | sed 's/^[ ;]*//; s/[ ;]*$//; s/; */; /g')"
    fi

    # 7.2 — Managed identities
    log "7.2 Checking VM managed identities..."
    local no_identity
    no_identity=$(echo "$vms" | jq '[.[] | select(.identity==null or .identity.type==null)] | length' 2>/dev/null || echo "0")
    if [[ "$no_identity" -eq 0 ]]; then
        pass "7.2 All VMs have managed identities configured"
        add_finding "EXT-VM1" "VirtualMachines" "VM Managed Identity" "PASS" "Info" \
            "All VMs have managed identities assigned." "" "Extended check (no CIS control)"
    else
        warn "7.2 $no_identity VM(s) without managed identity"
        add_finding "EXT-VM1" "VirtualMachines" "VM Managed Identity" "WARN" "Low" \
            "$no_identity VM(s) do not have a managed identity — these may use stored credentials for Azure resource access." \
            "Assign system-assigned managed identities to VMs that need Azure resource access. Avoid storing credentials in VMs." \
            "CIS 7.x | https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/"
    fi
}

# =============================================================================
# SECTION 8: KEY VAULT
# =============================================================================

assess_keyvault() {
    echo -e "\n${BOLD}━━━ Section 8: Key Vault ━━━${RESET}"

    log "8.x Enumerating Key Vaults..."
    local vaults
    vaults=$(az_query keyvault list -o json 2>/dev/null || echo "[]")
    local vault_count
    vault_count=$(echo "$vaults" | jq 'length' 2>/dev/null || echo "0")
    log "Found $vault_count Key Vault(s)"

    if [[ "$vault_count" -eq 0 ]]; then
        info "8.x No Key Vaults found"
        add_finding "8.0" "KeyVault" "Key Vault Presence" "PASS" "Info" "No Key Vaults found in scope." "" "CIS 8.x"
        return
    fi

    # 8.1 — Soft delete and purge protection
    local no_softdelete
    no_softdelete=$(echo "$vaults" | jq '[.[] | select(.properties.enableSoftDelete!=true)] | length' 2>/dev/null || echo "0")
    local no_purge
    no_purge=$(echo "$vaults" | jq '[.[] | select(.properties.enablePurgeProtection!=true)] | length' 2>/dev/null || echo "0")

    if [[ "$no_softdelete" -eq 0 ]]; then
        pass "8.1 All Key Vaults have soft delete enabled"
        add_finding "8.5" "KeyVault" "Key Vault Soft Delete" "PASS" "Info" \
            "All $vault_count Key Vaults have soft delete enabled." "" "CIS 8.6"
    else
        fail "8.1 $no_softdelete Key Vault(s) missing soft delete"
        add_finding "8.5" "KeyVault" "Key Vault Soft Delete" "FAIL" "High" \
            "$no_softdelete Key Vault(s) do not have soft delete enabled — deleted secrets/keys cannot be recovered." \
            "Enable soft delete on all Key Vaults. Note: Cannot be disabled once enabled." \
            "CIS 8.6 | https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
    fi

    if [[ "$no_purge" -eq 0 ]]; then
        pass "8.2 All Key Vaults have purge protection enabled"
        add_finding "8.6" "KeyVault" "Key Vault Purge Protection" "PASS" "Info" \
            "All $vault_count Key Vaults have purge protection enabled." "" "CIS 8.6"
    else
        fail "8.2 $no_purge Key Vault(s) missing purge protection"
        add_finding "8.6" "KeyVault" "Key Vault Purge Protection" "FAIL" "High" \
            "$no_purge Key Vault(s) do not have purge protection — a compromised account could permanently destroy keys/secrets (ransomware risk)." \
            "Enable purge protection on all Key Vaults." \
            "CIS 8.6 | https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection"
    fi

    # 8.3 — RBAC vs access policies
    local legacy_ap
    legacy_ap=$(echo "$vaults" | jq '[.[] | select(.properties.enableRbacAuthorization!=true)] | length' 2>/dev/null || echo "0")
    if [[ "$legacy_ap" -eq 0 ]]; then
        pass "8.3 All Key Vaults use RBAC authorization"
        add_finding "8.3" "KeyVault" "Key Vault RBAC Authorization" "PASS" "Info" \
            "All Key Vaults use RBAC for authorization (preferred over access policies)." "" "CIS 8.x"
    else
        warn "8.3 $legacy_ap Key Vault(s) using legacy access policies"
        add_finding "8.3" "KeyVault" "Key Vault RBAC Authorization" "WARN" "Medium" \
            "$legacy_ap Key Vault(s) use legacy access policies rather than RBAC — granular control is limited." \
            "Migrate Key Vaults to RBAC-based authorization model for finer-grained, auditable access control." \
            "CIS 8.x | https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide"
    fi

    # 8.4 — Key/Secret expiry
    log "8.4 Checking for keys/secrets without expiry dates..."
    local no_expiry=0
    while IFS= read -r vault_json; do
        local vault_name
        vault_name=$(echo "$vault_json" | jq -r '.name')
        local keys_no_exp
        keys_no_exp=$(num "$(az_query keyvault key list --vault-name "$vault_name" \
            --query "[?attributes.expires==null] | length(@)" -o tsv 2>/dev/null)")
        local secs_no_exp
        secs_no_exp=$(num "$(az_query keyvault secret list --vault-name "$vault_name" \
            --query "[?attributes.expires==null] | length(@)" -o tsv 2>/dev/null)")
        no_expiry=$((no_expiry + keys_no_exp + secs_no_exp))
    done < <(echo "$vaults" | jq -c '.[]' 2>/dev/null)

    if [[ "$no_expiry" -eq 0 ]]; then
        pass "8.4 All keys and secrets have expiry dates"
        add_finding "8.4" "KeyVault" "Key/Secret Expiry Dates" "PASS" "Info" \
            "All Key Vault keys and secrets have expiry dates configured." "" "CIS 8.2,8.3"
    else
        fail "8.4 $no_expiry key(s)/secret(s) without expiry dates"
        add_finding "8.4" "KeyVault" "Key/Secret Expiry Dates" "FAIL" "Medium" \
            "$no_expiry keys/secrets found without expiry dates — credentials may be long-lived or never rotated." \
            "Set expiry dates on all Key Vault keys and secrets. Implement rotation policies." \
            "CIS 8.2,8.3 | https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys"
    fi
}

# =============================================================================
# SECTION 9: APP SERVICES
# =============================================================================

assess_appservice() {
    echo -e "\n${BOLD}━━━ Section 9: App Services ━━━${RESET}"

    log "9.x Enumerating App Services..."
    local apps
    apps=$(az_query webapp list -o json 2>/dev/null || echo "[]")
    local app_count
    app_count=$(echo "$apps" | jq 'length' 2>/dev/null || echo "0")
    log "Found $app_count App Service(s)"

    if [[ "$app_count" -eq 0 ]]; then
        info "9.x No App Services found"
        add_finding "9.0" "AppService" "App Service Presence" "PASS" "Info" "No App Services found in scope." "" "CIS 9.x"
        return
    fi

    # 9.1 — HTTPS only
    local http_apps
    http_apps=$(echo "$apps" | jq '[.[] | select(.httpsOnly!=true)] | length' 2>/dev/null || echo "0")
    if [[ "$http_apps" -eq 0 ]]; then
        pass "9.1 All App Services enforce HTTPS"
        add_finding "9.2" "AppService" "App Service HTTPS Only" "PASS" "Info" \
            "All $app_count App Services have HTTPS Only enabled." "" "CIS 9.2"
    else
        fail "9.1 $http_apps App Service(s) allow HTTP"
        add_finding "9.2" "AppService" "App Service HTTPS Only" "FAIL" "High" \
            "$http_apps App Service(s) do not enforce HTTPS — credentials and data transmitted in cleartext." \
            "Enable HTTPS Only on all App Services. Enforce minimum TLS 1.2." \
            "CIS 9.2 | https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings"
    fi

    # 9.2 — Remote debugging
    log "9.2 Checking for remote debugging enabled..."
    local debug_on=0
    while IFS= read -r app_json; do
        local app_name app_rg
        app_name=$(echo "$app_json" | jq -r '.name')
        app_rg=$(echo "$app_json" | jq -r '.resourceGroup')
        local debug
        debug=$(az_query webapp config show \
            --name "$app_name" --resource-group "$app_rg" \
            --query "remoteDebuggingEnabled" -o tsv 2>/dev/null || echo "false")
        if [[ "$debug" == "true" ]]; then
            debug_on=$((debug_on + 1))
        fi
    done < <(echo "$apps" | jq -c '.[]' 2>/dev/null)

    if [[ "$debug_on" -eq 0 ]]; then
        pass "9.2 Remote debugging disabled on all App Services"
        add_finding "9.6" "AppService" "App Service Remote Debugging" "PASS" "Info" \
            "Remote debugging is disabled across all App Services." "" "CIS 9.3"
    else
        fail "9.2 $debug_on App Service(s) have remote debugging enabled"
        add_finding "9.6" "AppService" "App Service Remote Debugging" "FAIL" "High" \
            "$debug_on App Service(s) have remote debugging enabled — exposes debugging endpoints that could be exploited." \
            "Disable remote debugging on all App Services in production." \
            "CIS 9.3 | https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-dotnet-visual-studio"
    fi

    # 9.3 — Managed identity
    local no_identity_apps
    no_identity_apps=$(echo "$apps" | jq '[.[] | select(.identity==null or .identity.type==null)] | length' 2>/dev/null || echo "0")
    if [[ "$no_identity_apps" -eq 0 ]]; then
        pass "9.3 All App Services have managed identities"
        add_finding "9.5" "AppService" "App Service Managed Identity" "PASS" "Info" \
            "All App Services have managed identities configured." "" "CIS 9.x"
    else
        warn "9.3 $no_identity_apps App Service(s) without managed identity"
        add_finding "9.5" "AppService" "App Service Managed Identity" "WARN" "Medium" \
            "$no_identity_apps App Service(s) without managed identity — likely using stored credentials or connection strings." \
            "Enable system-assigned managed identities on all App Services requiring Azure resource access." \
            "CIS 9.x | https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity"
    fi

    # 9.4 — App Service minimum TLS version
    log "9.4 Checking App Service minimum TLS version..."
    local low_tls_apps=0
    while IFS= read -r app_json; do
        local app_name app_rg
        app_name=$(echo "$app_json" | jq -r '.name')
        app_rg=$(echo "$app_json" | jq -r '.resourceGroup')
        local min_tls
        min_tls=$(az_query webapp config show \
            --name "$app_name" --resource-group "$app_rg" \
            --query "minTlsVersion" -o tsv 2>/dev/null || echo "unknown")
        if [[ "$min_tls" != "1.2" && "$min_tls" != "1.3" && "$min_tls" != "unknown" ]]; then
            low_tls_apps=$((low_tls_apps + 1))
        fi
    done < <(echo "$apps" | jq -c '.[]' 2>/dev/null)

    if [[ "$low_tls_apps" -eq 0 ]]; then
        pass "9.4 All App Services enforce TLS 1.2+"
        add_finding "9.3" "AppService" "App Service Minimum TLS" "PASS" "Info" \
            "All App Services enforce TLS 1.2 or higher." "" "CIS 9.x"
    else
        fail "9.4 $low_tls_apps App Service(s) allow TLS below 1.2"
        add_finding "9.3" "AppService" "App Service Minimum TLS" "FAIL" "Medium" \
            "$low_tls_apps App Service(s) permit TLS below 1.2 — vulnerable to protocol downgrade." \
            "Set minimum TLS version to 1.2 on all App Services." \
            "CIS 9.x | https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings"
    fi

    # 9.5 — FTP state (should be Disabled or FtpsOnly)
    log "9.5 Checking App Service FTP deployment state..."
    local ftp_insecure=0
    local ftp_names=""
    while IFS= read -r app_json; do
        local app_name app_rg
        app_name=$(echo "$app_json" | jq -r '.name')
        app_rg=$(echo "$app_json" | jq -r '.resourceGroup')
        local ftp_state
        ftp_state=$(az_query webapp config show \
            --name "$app_name" --resource-group "$app_rg" \
            --query "ftpsState" -o tsv 2>/dev/null || echo "unknown")
        if [[ "$ftp_state" == "AllAllowed" ]]; then
            ftp_insecure=$((ftp_insecure + 1))
            ftp_names="$ftp_names $app_name;"
        fi
    done < <(echo "$apps" | jq -c '.[]' 2>/dev/null)

    if [[ "$ftp_insecure" -eq 0 ]]; then
        pass "9.5 No App Services allow plain FTP"
        add_finding "9.9" "AppService" "App Service FTP State" "PASS" "Info" \
            "No App Services allow insecure plain FTP deployments." "" "CIS 9.10"
    else
        fail "9.5 $ftp_insecure App Service(s) allow plain FTP: $ftp_names"
        add_finding "9.9" "AppService" "App Service FTP State" "FAIL" "Medium" \
            "$ftp_insecure App Service(s) allow plaintext FTP: $ftp_names — credentials transmitted in cleartext." \
            "Set FTP state to 'FTPS Only' or 'Disabled' on all App Services." \
            "CIS 9.9 | https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp" \
            "$(echo "$ftp_names" | sed 's/^[ ;]*//; s/[ ;]*$//; s/; */; /g')"
    fi

    # 9.6 — Client certificates / HTTP 2.0
    log "9.6 Checking App Service HTTP version..."
    local http1_apps=0
    while IFS= read -r app_json; do
        local app_name app_rg
        app_name=$(echo "$app_json" | jq -r '.name')
        app_rg=$(echo "$app_json" | jq -r '.resourceGroup')
        local http20
        http20=$(az_query webapp config show \
            --name "$app_name" --resource-group "$app_rg" \
            --query "http20Enabled" -o tsv 2>/dev/null || echo "unknown")
        if [[ "$http20" == "false" ]]; then
            http1_apps=$((http1_apps + 1))
        fi
    done < <(echo "$apps" | jq -c '.[]' 2>/dev/null)

    if [[ "$http1_apps" -eq 0 ]]; then
        pass "9.6 HTTP/2 enabled on all App Services"
        add_finding "9.10" "AppService" "App Service HTTP/2" "PASS" "Info" \
            "HTTP/2 is enabled on all App Services." "" "CIS 9.10"
    else
        warn "9.6 $http1_apps App Service(s) without HTTP/2"
        add_finding "9.10" "AppService" "App Service HTTP/2" "WARN" "Low" \
            "$http1_apps App Service(s) do not have HTTP/2 enabled." \
            "Enable HTTP/2 for improved performance and security on all App Services." \
            "CIS 9.10 | https://learn.microsoft.com/en-us/azure/app-service/configure-common"
    fi
}

# =============================================================================
# SECTION 10: SUBSCRIPTION & RESOURCE GOVERNANCE
# =============================================================================

assess_governance() {
    echo -e "\n${BOLD}━━━ Section 10: Subscription & Governance ━━━${RESET}"

    # 10.1 — Azure Policy assignments
    log "10.1 Checking Azure Policy assignments..."
    local policies
    policies=$(az_query policy assignment list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$policies" -gt 0 ]] 2>/dev/null; then
        pass "10.1 $policies Azure Policy assignment(s) found"
        add_finding "EXT-GOV1" "Governance" "Azure Policy Assignments" "PASS" "Info" \
            "$policies Azure Policy assignments are in place for governance enforcement." "" "Extended check (no CIS control)"
    else
        warn "10.1 No Azure Policy assignments found"
        add_finding "EXT-GOV1" "Governance" "Azure Policy Assignments" "WARN" "Medium" \
            "No Azure Policy assignments detected — no automated governance/compliance enforcement is configured." \
            "Assign Azure Policy initiatives (e.g. CIS, Azure Security Benchmark) to enforce baseline compliance." \
            "Extended check (no CIS control)"
    fi

    # 10.2 — Resource locks on critical resource groups
    log "10.2 Checking for resource locks..."
    local locks
    locks=$(az_query lock list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$locks" -gt 0 ]] 2>/dev/null; then
        pass "10.2 $locks resource lock(s) configured"
        add_finding "EXT-GOV2" "Governance" "Resource Locks" "PASS" "Info" \
            "$locks resource lock(s) protect against accidental deletion/modification." "" "Extended check (no CIS control)"
    else
        warn "10.2 No resource locks found"
        add_finding "EXT-GOV2" "Governance" "Resource Locks" "WARN" "Low" \
            "No resource locks configured — critical resources are vulnerable to accidental or malicious deletion." \
            "Apply CanNotDelete or ReadOnly locks on production resource groups and critical resources." \
            "Extended check (no CIS control)"
    fi

    # 10.3 — Management groups
    log "10.3 Checking management group structure..."
    local mgmt_groups
    mgmt_groups=$(az_query account management-group list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$mgmt_groups" -gt 0 ]] 2>/dev/null; then
        pass "10.3 Management group hierarchy in use ($mgmt_groups groups)"
        add_finding "EXT-GOV3" "Governance" "Management Groups" "PASS" "Info" \
            "$mgmt_groups management group(s) provide hierarchical governance." "" "Extended check (no CIS control)"
    else
        info "10.3 No custom management groups (single subscription may not require them)"
        add_finding "EXT-GOV3" "Governance" "Management Groups" "MANUAL" "Low" \
            "No custom management groups found. For single-tenant single-subscription setups this may be acceptable." \
            "For multi-subscription environments, use management groups to apply policy and RBAC at scale." \
            "Extended check (no CIS control)"
    fi
}

# =============================================================================
# SECTION 11: ENTRA ID (AAD) ADVANCED
# =============================================================================

assess_entra_advanced() {
    echo -e "\n${BOLD}━━━ Section 11: Entra ID Advanced ━━━${RESET}"

    # 11.1 — App registrations with credentials
    log "11.1 Checking app registrations for credentials..."
    local apps_with_creds
    apps_with_creds=$(az_query ad app list --all \
        --query "[?length(passwordCredentials) > \`0\`] | length(@)" -o tsv 2>/dev/null || echo "unknown")
    if [[ "$apps_with_creds" == "0" ]]; then
        pass "11.1 No app registrations with password credentials"
        add_finding "EXT-EID1" "EntraID" "App Registration Secrets" "PASS" "Info" \
            "No app registrations rely on client secret credentials." "" "CIS 1.x"
    elif [[ "$apps_with_creds" == "unknown" ]]; then
        warn "11.1 Could not enumerate app credentials"
        add_finding "EXT-EID1" "EntraID" "App Registration Secrets" "ERROR" "Medium" \
            "Failed to enumerate app registration credentials — check permissions." \
            "Review app registrations manually for long-lived secrets." "CIS 1.x"
    else
        warn "11.1 $apps_with_creds app registration(s) use password credentials"
        add_finding "EXT-EID1" "EntraID" "App Registration Secrets" "WARN" "Medium" \
            "$apps_with_creds app registration(s) use client secrets — prefer certificate credentials or managed identities." \
            "Migrate to certificate-based credentials or managed identities. Audit secret expiry and rotation." \
            "CIS 1.x | https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal"
    fi

    # 11.2 — Users allowed to register applications
    log "11.2 Checking user app registration permissions..."
    local user_can_register
    user_can_register=$(az_query rest --method GET \
        --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
        --query "defaultUserRolePermissions.allowedToCreateApps" -o tsv 2>/dev/null || echo "unknown")
    if [[ "$user_can_register" == "false" ]]; then
        pass "11.2 Users cannot register applications"
        add_finding "1.11" "EntraID" "User App Registration" "PASS" "Info" \
            "Standard users are not permitted to register applications." "" "CIS 1.11"
    elif [[ "$user_can_register" == "true" ]]; then
        fail "11.2 Users CAN register applications"
        add_finding "1.11" "EntraID" "User App Registration" "FAIL" "Medium" \
            "Any user can register applications — increases attack surface for consent phishing and rogue apps." \
            "Restrict app registration to administrators in Entra ID > User Settings." \
            "CIS 1.11 | https://learn.microsoft.com/en-us/azure/active-directory/roles/delegate-app-roles"
    else
        add_finding "1.11" "EntraID" "User App Registration" "MANUAL" "Medium" \
            "Could not determine app registration policy via CLI." \
            "Verify in Entra ID > User Settings > App registrations." "CIS 1.11"
    fi

    # 11.3 — Users can consent to apps
    log "11.3 Checking user consent settings..."
    local consent_policy
    consent_policy=$(az_query rest --method GET \
        --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
        --query "defaultUserRolePermissions.permissionGrantPoliciesAssigned" -o json 2>/dev/null || echo "[]")
    local consent_count
    consent_count=$(echo "$consent_policy" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$consent_count" -eq 0 ]]; then
        pass "11.3 User consent to apps is restricted"
        add_finding "1.x" "EntraID" "User Consent to Apps" "PASS" "Info" \
            "Users cannot independently consent to third-party applications." "" "CIS 1.x"
    else
        warn "11.3 Users may be able to consent to applications"
        add_finding "1.x" "EntraID" "User Consent to Apps" "WARN" "Medium" \
            "User consent permission grant policies are assigned — users may grant data access to third-party apps (consent phishing risk)." \
            "Require admin consent for apps accessing company data. Configure consent settings in Entra ID > Enterprise Applications." \
            "CIS 1.x | https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent"
    fi

    # 11.4 — Security groups / role-assignable groups
    log "11.4 Checking custom directory roles..."
    local custom_roles
    custom_roles=$(az_query rest --method GET \
        --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?\$filter=isBuiltIn eq false" \
        --query "value | length(@)" -o tsv 2>/dev/null || echo "0")
    info "11.4 $custom_roles custom directory role(s) found"
    add_finding "EXT-EID2" "EntraID" "Custom Directory Roles" "MANUAL" "Low" \
        "$custom_roles custom directory roles defined. Review each for least-privilege adherence." \
        "Audit custom directory roles to ensure they do not grant excessive permissions." \
        "CIS 1.x | https://learn.microsoft.com/en-us/azure/active-directory/roles/custom-overview"
}

# =============================================================================
# SECTION 12: DISKS, SNAPSHOTS & DATA
# =============================================================================

assess_data_resources() {
    echo -e "\n${BOLD}━━━ Section 12: Disks, Snapshots & Backup ━━━${RESET}"

    # 12.1 — Unattached managed disks (potential data leakage)
    log "12.1 Checking for unattached managed disks..."
    local disks
    disks=$(az_query disk list -o json 2>/dev/null || echo "[]")
    local unattached
    unattached=$(echo "$disks" | jq '[.[] | select(.diskState=="Unattached")] | length' 2>/dev/null || echo "0")
    if [[ "$unattached" -eq 0 ]]; then
        pass "12.1 No unattached managed disks"
        add_finding "EXT-DISK1" "DataResources" "Unattached Managed Disks" "PASS" "Info" \
            "No unattached managed disks present." "" "Extended check (no CIS control)"
    else
        warn "12.1 $unattached unattached managed disk(s) found"
        add_finding "EXT-DISK1" "DataResources" "Unattached Managed Disks" "WARN" "Low" \
            "$unattached unattached managed disk(s) found — orphaned disks may retain sensitive data and incur cost." \
            "Review and delete orphaned disks, or ensure they remain encrypted. Document retention justification." \
            "CIS 7.x | https://learn.microsoft.com/en-us/azure/virtual-machines/disks-find-unattached-portal"
    fi

    # 12.2 — Managed disk encryption type
    log "12.2 Checking managed disk encryption..."
    local platform_only
    platform_only=$(echo "$disks" | jq '[.[] | select(.encryption.type=="EncryptionAtRestWithPlatformKey")] | length' 2>/dev/null || echo "0")
    local total_disks
    total_disks=$(echo "$disks" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$total_disks" -eq 0 ]]; then
        info "12.2 No managed disks found"
        add_finding "7.3" "DataResources" "Managed Disk Encryption" "PASS" "Info" "No managed disks in scope." "" "Extended check (no CIS control)"
    elif [[ "$platform_only" -eq 0 ]]; then
        pass "12.2 All disks use customer-managed or double encryption"
        add_finding "7.3" "DataResources" "Managed Disk Encryption" "PASS" "Info" \
            "All managed disks use CMK or enhanced encryption." "" "Extended check (no CIS control)"
    else
        warn "12.2 $platform_only/$total_disks disk(s) use platform-managed keys only"
        add_finding "7.3" "DataResources" "Managed Disk Encryption" "WARN" "Low" \
            "$platform_only of $total_disks managed disks use platform-managed keys only — consider CMK for sensitive workloads." \
            "Evaluate customer-managed keys (CMK) for disks holding sensitive data, for greater key control." \
            "CIS 7.x | https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption"
    fi

    # 12.3 — Public snapshots
    log "12.3 Checking disk snapshots..."
    local snapshots
    snapshots=$(az_query snapshot list --query "length(@)" -o tsv 2>/dev/null || echo "0")
    info "12.3 $snapshots snapshot(s) found"
    add_finding "EXT-DISK2" "DataResources" "Disk Snapshots" "MANUAL" "Low" \
        "$snapshots disk snapshot(s) found. Review export/SAS access on each — snapshots can leak full disk contents." \
        "Ensure snapshots are not exposed via public SAS tokens. Apply RBAC and encryption." \
        "CIS 7.x | https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk"
}

# =============================================================================
# SECTION 13: COSMOS DB & OTHER DATA SERVICES
# =============================================================================

assess_other_data() {
    echo -e "\n${BOLD}━━━ Section 13: Cosmos DB & PaaS Data ━━━${RESET}"

    # 13.1 — Cosmos DB accounts
    log "13.1 Checking Cosmos DB accounts..."
    local cosmos
    cosmos=$(az_query cosmosdb list -o json 2>/dev/null || echo "[]")
    local cosmos_count
    cosmos_count=$(echo "$cosmos" | jq 'length' 2>/dev/null || echo "0")

    if [[ "$cosmos_count" -eq 0 ]]; then
        info "13.1 No Cosmos DB accounts found"
        add_finding "4.5" "PaaSData" "Cosmos DB Presence" "PASS" "Info" "No Cosmos DB accounts in scope." "" "CIS 4.x"
    else
        # Check for accounts allowing access from all networks
        local open_cosmos
        open_cosmos=$(echo "$cosmos" | jq '[.[] | select((.ipRules | length)==0 and .isVirtualNetworkFilterEnabled==false)] | length' 2>/dev/null || echo "0")
        if [[ "$open_cosmos" -eq 0 ]]; then
            pass "13.1 All Cosmos DB accounts have network restrictions"
            add_finding "4.5" "PaaSData" "Cosmos DB Network Access" "PASS" "Info" \
                "All $cosmos_count Cosmos DB accounts restrict network access." "" "CIS 4.x"
        else
            fail "13.1 $open_cosmos Cosmos DB account(s) allow access from all networks"
            add_finding "4.5" "PaaSData" "Cosmos DB Network Access" "FAIL" "High" \
                "$open_cosmos Cosmos DB account(s) accept connections from any network — broad data exposure surface." \
                "Configure IP firewall rules or VNet service endpoints / Private Endpoints on Cosmos DB accounts." \
                "CIS 4.x | https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall"
        fi
    fi

    # 13.2 — Redis Cache non-SSL port
    log "13.2 Checking Redis Cache instances..."
    local redis
    redis=$(az_query redis list -o json 2>/dev/null || echo "[]")
    local redis_count
    redis_count=$(echo "$redis" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$redis_count" -eq 0 ]]; then
        info "13.2 No Redis Cache instances found"
        add_finding "EXT-DB1" "PaaSData" "Redis Cache" "PASS" "Info" "No Redis Cache instances in scope." "" "CIS 4.x"
    else
        local nonssl
        nonssl=$(echo "$redis" | jq '[.[] | select(.enableNonSslPort==true)] | length' 2>/dev/null || echo "0")
        if [[ "$nonssl" -eq 0 ]]; then
            pass "13.2 All Redis Cache instances require SSL"
            add_finding "EXT-DB1" "PaaSData" "Redis Non-SSL Port" "PASS" "Info" \
                "All Redis Cache instances have the non-SSL port disabled." "" "CIS 4.x"
        else
            fail "13.2 $nonssl Redis Cache instance(s) allow non-SSL connections"
            add_finding "EXT-DB1" "PaaSData" "Redis Non-SSL Port" "FAIL" "High" \
                "$nonssl Redis Cache instance(s) have the non-SSL port (6379) enabled — data transmitted in cleartext." \
                "Disable the non-SSL port. Use only the SSL port (6380) for all Redis connections." \
                "CIS 4.x | https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-configure"
        fi
    fi

    # 13.3 — PostgreSQL / MySQL flexible servers SSL enforcement
    log "13.3 Checking PostgreSQL servers..."
    local pg
    pg=$(az_query postgres flexible-server list -o json 2>/dev/null || echo "[]")
    local pg_count
    pg_count=$(echo "$pg" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$pg_count" -eq 0 ]]; then
        info "13.3 No PostgreSQL flexible servers found"
        add_finding "4.3" "PaaSData" "PostgreSQL Servers" "PASS" "Info" "No PostgreSQL flexible servers in scope." "" "CIS 4.x"
    else
        info "13.3 $pg_count PostgreSQL server(s) found — verify SSL enforcement and firewall"
        add_finding "4.3" "PaaSData" "PostgreSQL Servers" "MANUAL" "Medium" \
            "$pg_count PostgreSQL flexible server(s) found. Verify require_secure_transport=ON and firewall rules." \
            "Ensure SSL/TLS enforcement is enabled and firewall does not permit 0.0.0.0. Use Private Endpoints." \
            "CIS 4.x | https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking"
    fi
}

# =============================================================================
# SECTION 14: CONTAINER & KUBERNETES SECURITY
# =============================================================================

assess_containers() {
    echo -e "\n${BOLD}━━━ Section 14: Containers & Kubernetes ━━━${RESET}"

    # 14.1 — AKS clusters
    log "14.1 Checking AKS clusters..."
    local aks
    aks=$(az_query aks list -o json 2>/dev/null || echo "[]")
    local aks_count
    aks_count=$(echo "$aks" | jq 'length' 2>/dev/null || echo "0")

    if [[ "$aks_count" -eq 0 ]]; then
        info "14.1 No AKS clusters found"
        add_finding "EXT-AKS0" "Containers" "AKS Presence" "PASS" "Info" "No AKS clusters in scope." "" "CIS 8.x"
    else
        # RBAC enabled
        local no_rbac
        no_rbac=$(echo "$aks" | jq '[.[] | select(.enableRbac!=true)] | length' 2>/dev/null || echo "0")
        if [[ "$no_rbac" -eq 0 ]]; then
            pass "14.1 All AKS clusters have RBAC enabled"
            add_finding "EXT-AKS1" "Containers" "AKS RBAC" "PASS" "Info" \
                "All $aks_count AKS clusters have Kubernetes RBAC enabled." "" "CIS 8.x"
        else
            fail "14.1 $no_rbac AKS cluster(s) without RBAC"
            add_finding "EXT-AKS1" "Containers" "AKS RBAC" "FAIL" "High" \
                "$no_rbac AKS cluster(s) do not have RBAC enabled — no granular authorisation in-cluster." \
                "Enable Kubernetes RBAC. Note RBAC cannot be enabled on existing clusters — requires recreation." \
                "CIS 8.x | https://learn.microsoft.com/en-us/azure/aks/azure-ad-rbac"
        fi

        # Private cluster check
        local public_aks
        public_aks=$(echo "$aks" | jq '[.[] | select(.apiServerAccessProfile.enablePrivateCluster!=true)] | length' 2>/dev/null || echo "0")
        if [[ "$public_aks" -eq 0 ]]; then
            pass "14.2 All AKS clusters use private API servers"
            add_finding "EXT-AKS2" "Containers" "AKS Private Cluster" "PASS" "Info" \
                "All AKS clusters use private API server endpoints." "" "CIS 8.x"
        else
            warn "14.2 $public_aks AKS cluster(s) have public API servers"
            add_finding "EXT-AKS2" "Containers" "AKS Private Cluster" "WARN" "High" \
                "$public_aks AKS cluster(s) expose the Kubernetes API server publicly." \
                "Use private clusters or authorised IP ranges to restrict API server access." \
                "CIS 8.x | https://learn.microsoft.com/en-us/azure/aks/private-clusters"
        fi
    fi

    # 14.3 — Azure Container Registry
    log "14.3 Checking Container Registries..."
    local acr
    acr=$(az_query acr list -o json 2>/dev/null || echo "[]")
    local acr_count
    acr_count=$(echo "$acr" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$acr_count" -eq 0 ]]; then
        info "14.3 No Container Registries found"
        add_finding "EXT-ACR0" "Containers" "ACR Presence" "PASS" "Info" "No Container Registries in scope." "" "CIS 8.x"
    else
        local admin_enabled
        admin_enabled=$(echo "$acr" | jq '[.[] | select(.adminUserEnabled==true)] | length' 2>/dev/null || echo "0")
        if [[ "$admin_enabled" -eq 0 ]]; then
            pass "14.3 No ACR with admin user enabled"
            add_finding "EXT-ACR1" "Containers" "ACR Admin User" "PASS" "Info" \
                "No Container Registries have the admin user account enabled." "" "CIS 8.x"
        else
            fail "14.3 $admin_enabled ACR(s) have admin user enabled"
            add_finding "EXT-ACR1" "Containers" "ACR Admin User" "FAIL" "Medium" \
                "$admin_enabled Container Registry/Registries have the admin user enabled — a single shared credential rather than per-identity access." \
                "Disable the ACR admin user. Use Entra ID identities and RBAC / token-based access." \
                "CIS 8.x | https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication"
        fi
    fi
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

generate_json() {
    log "Generating JSON report..."
    local sub_info
    sub_info=$(az_query account show -o json 2>/dev/null || echo '{"name":"unknown","id":"unknown","tenantId":"unknown"}')
    local sub_name sub_id tenant_id
    sub_name=$(echo "$sub_info" | jq -r '.name // "unknown"')
    sub_id=$(echo "$sub_info" | jq -r '.id // "unknown"')
    tenant_id=$(echo "$sub_info" | jq -r '.tenantId // "unknown"')

    # Count total evidence artifacts captured
    local evidence_count
    evidence_count=$(echo "$FINDINGS" | jq '[.[].evidence[]?] | length' 2>/dev/null || echo 0)

    # Build the whole document with jq so arbitrary evidence output cannot
    # produce malformed JSON.
    jq -n \
        --arg generated "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg sub_name "$sub_name" \
        --arg sub_id "$sub_id" \
        --arg tenant_id "$tenant_id" \
        --arg evidence_dir "evidence/" \
        --argjson total "$TOTAL" \
        --argjson pass "$PASS" \
        --argjson fail "$FAIL" \
        --argjson warn "$WARN" \
        --argjson manual "$MANUAL" \
        --argjson error "$ERROR" \
        --argjson evidence_count "${evidence_count:-0}" \
        --argjson findings "$FINDINGS" \
        '{
          report: {
            title: "Azure CIS Benchmark Assessment",
            generated: $generated,
            tool: "azure_cis_assessment.sh v2.0",
            benchmark: "CIS Microsoft Azure Foundations Benchmark v6.0.0",
            author: "URM Consulting",
            subscription: { name: $sub_name, id: $sub_id, tenantId: $tenant_id },
            evidence: { directory: $evidence_dir, artifacts_captured: $evidence_count },
            summary: { total: $total, pass: $pass, fail: $fail, warn: $warn, manual: $manual, error: $error },
            findings: $findings
          }
        }' > "$JSON_FILE"

    pass "JSON report: $JSON_FILE ($evidence_count evidence artifacts referenced)"
}

generate_html() {
    log "Generating HTML report..."
    local sub_info
    sub_info=$(az_query account show -o json 2>/dev/null || echo '{"name":"unknown","id":"unknown","tenantId":"unknown"}')
    local sub_name sub_id tenant_id
    sub_name=$(echo "$sub_info" | jq -r '.name // "unknown"')
    sub_id=$(echo "$sub_info" | jq -r '.id // "unknown"')
    tenant_id=$(echo "$sub_info" | jq -r '.tenantId // "unknown"')

    local score_pct=0
    if [[ "$TOTAL" -gt 0 ]]; then
        score_pct=$(( (PASS * 100) / TOTAL ))
    fi

    # Write findings JSON to a temp file for Python to parse and render safely
    # (evidence output may contain arbitrary characters; let Python handle escaping).
    local findings_tmp
    findings_tmp=$(mktemp)
    echo "$FINDINGS" > "$findings_tmp"

    # Domain summary
    local domain_rows=""
    while IFS= read -r domain; do
        local d_total d_pass d_fail d_warn
        d_total=$(echo "$FINDINGS" | jq --arg d "$domain" '[.[] | select(.domain==$d)] | length' 2>/dev/null || echo 0)
        d_pass=$(echo "$FINDINGS" | jq --arg d "$domain" '[.[] | select(.domain==$d and .status=="PASS")] | length' 2>/dev/null || echo 0)
        d_fail=$(echo "$FINDINGS" | jq --arg d "$domain" '[.[] | select(.domain==$d and .status=="FAIL")] | length' 2>/dev/null || echo 0)
        d_warn=$(echo "$FINDINGS" | jq --arg d "$domain" '[.[] | select(.domain==$d and .status=="WARN")] | length' 2>/dev/null || echo 0)
        domain_rows+="<tr><td>$domain</td><td>$d_total</td><td class='pass'>$d_pass</td><td class='fail'>$d_fail</td><td class='warn'>$d_warn</td></tr>"
    done < <(echo "$FINDINGS" | jq -r '[.[].domain] | unique[]' 2>/dev/null)

    FINDINGS_TMP="$findings_tmp" python3 - <<PYEOF > "$HTML_FILE"
import os, json, html as _html

with open(os.environ["FINDINGS_TMP"]) as fh:
    findings = json.load(fh)

def esc(s):
    return _html.escape(str(s if s is not None else ""))

status_class = {"PASS":"status-pass","FAIL":"status-fail","WARN":"status-warn","MANUAL":"status-manual"}
sev_class = {"Critical":"sev-critical","High":"sev-high","Medium":"sev-medium","Low":"sev-low"}

row_parts = []
for idx, f in enumerate(findings):
    cid = esc(f.get("cis_id"))
    cid_class = "cid-ext" if str(f.get("cis_id","")).startswith("EXT") else "cid-cis"
    domain = esc(f.get("domain"))
    title = esc(f.get("title"))
    status = esc(f.get("status"))
    severity = esc(f.get("severity"))
    detail = esc(f.get("detail"))
    rec = esc(f.get("recommendation"))
    affected = esc(f.get("affected_systems"))
    sc = status_class.get(f.get("status"), "status-error")
    vc = sev_class.get(f.get("severity"), "sev-info")
    evidence = f.get("evidence", []) or []
    ev_count = len(evidence)

    # Build evidence panel content
    ev_blocks = []
    for ev in evidence:
        cmd = esc(ev.get("command"))
        ts = esc(ev.get("timestamp"))
        code = esc(ev.get("exit_code"))
        out = esc(ev.get("output"))
        err = esc(ev.get("stderr"))
        artifact = esc(ev.get("artifact"))
        block = f'''<div class="ev-block">
          <div class="ev-cmd"><span class="ev-prompt">$</span> {cmd}</div>
          <div class="ev-meta">exit {code} &middot; {ts} &middot; <span class="ev-file">evidence/{artifact}</span></div>
          <pre class="ev-out">{out if out.strip() else "(no stdout)"}</pre>'''
        if err.strip():
            block += f'<pre class="ev-err">{err}</pre>'
        block += '</div>'
        ev_blocks.append(block)
    ev_html = "".join(ev_blocks) if ev_blocks else '<div class="ev-empty">No commands captured for this check.</div>'

    affected_html = f'<div class="affected-row"><span class="affected-label">Affected:</span> {affected}</div>' if affected.strip() else ''

    toggle = f'<button class="ev-toggle" onclick="toggleEv({idx})">▸ {ev_count} cmd{"s" if ev_count!=1 else ""}</button>' if ev_count else '<span class="ev-none">—</span>'

    row_parts.append(f'''<tr class="finding-row" data-status="{status}">
        <td><code class="{cid_class}">{cid}</code></td>
        <td><span class='domain-badge'>{domain}</span></td>
        <td>{title}{affected_html}</td>
        <td><span class='status-badge {sc}'>{status}</span></td>
        <td><span class='sev-badge {vc}'>{severity}</span></td>
        <td class='detail-cell'>{detail}</td>
        <td class='detail-cell'>{rec}</td>
        <td class="ev-toggle-cell">{toggle}</td>
    </tr>
    <tr class="ev-row" id="ev-{idx}" data-status="{status}" style="display:none">
        <td colspan="8"><div class="ev-panel">{ev_html}</div></td>
    </tr>''')

rows = "".join(row_parts)
domain_rows = """$domain_rows"""
sub_name = "$sub_name"
sub_id = "$sub_id"
tenant_id = "$tenant_id"
score_pct = $score_pct
total = $TOTAL
passed = $PASS
failed = $FAIL
warned = $WARN
manual = $MANUAL
ts = "$(date)"
evidence_total = sum(len(f.get("evidence", []) or []) for f in findings)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure CIS Assessment — URM Consulting</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0c10;
    --surface: #111418;
    --surface2: #181c22;
    --border: #22272e;
    --accent: #58a6ff;
    --accent2: #3fb950;
    --red: #f85149;
    --yellow: #e3b341;
    --purple: #bc8cff;
    --mono: 'IBM Plex Mono', monospace;
    --sans: 'IBM Plex Sans', sans-serif;
    --text: #c9d1d9;
    --muted: #6e7681;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 48px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -40%;
    right: -10%;
    width: 600px;
    height: 600px;
    background: radial-gradient(circle, rgba(88,166,255,0.06) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-grid {{
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: start;
    gap: 24px;
    max-width: 1400px;
    margin: 0 auto;
  }}
  .logo {{
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .logo::before {{
    content: '▶';
    font-size: 8px;
  }}
  h1 {{
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
  }}
  .subtitle {{
    font-size: 13px;
    color: var(--muted);
    font-family: var(--mono);
  }}
  .meta-pills {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 20px;
  }}
  .pill {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 12px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
  }}
  .pill span {{ color: var(--text); }}

  /* ── Score Widget ── */
  .score-widget {{
    text-align: center;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px 32px;
    min-width: 180px;
  }}
  .score-num {{
    font-family: var(--mono);
    font-size: 52px;
    font-weight: 700;
    line-height: 1;
    color: {'#3fb950' if score_pct >= 70 else ('#e3b341' if score_pct >= 50 else '#f85149')};
  }}
  .score-label {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 4px;
  }}
  .score-bar {{
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    margin-top: 12px;
    overflow: hidden;
  }}
  .score-fill {{
    height: 100%;
    width: {score_pct}%;
    background: {'#3fb950' if score_pct >= 70 else ('#e3b341' if score_pct >= 50 else '#f85149')};
    border-radius: 2px;
    transition: width 1s ease;
  }}

  /* ── Main Layout ── */
  .main {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 32px 48px 64px;
  }}

  /* ── Stats Grid ── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::after {{
    content: '';
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 2px;
  }}
  .stat-card.c-total::after {{ background: var(--accent); }}
  .stat-card.c-pass::after {{ background: var(--accent2); }}
  .stat-card.c-fail::after {{ background: var(--red); }}
  .stat-card.c-warn::after {{ background: var(--yellow); }}
  .stat-card.c-manual::after {{ background: var(--purple); }}
  .stat-num {{
    font-family: var(--mono);
    font-size: 36px;
    font-weight: 700;
    line-height: 1;
  }}
  .c-total .stat-num {{ color: var(--accent); }}
  .c-pass .stat-num {{ color: var(--accent2); }}
  .c-fail .stat-num {{ color: var(--red); }}
  .c-warn .stat-num {{ color: var(--yellow); }}
  .c-manual .stat-num {{ color: var(--purple); }}
  .stat-label {{
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 6px;
  }}

  /* ── Section Title ── */
  .section-title {{
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  /* ── Domain Summary ── */
  .domain-table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 32px;
  }}
  .domain-table {{
    width: 100%;
    border-collapse: collapse;
  }}
  .domain-table th {{
    background: var(--surface2);
    padding: 10px 16px;
    text-align: left;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
  }}
  .domain-table td {{
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 13px;
  }}
  .domain-table tr:last-child td {{ border-bottom: none; }}
  .domain-table td.pass {{ color: var(--accent2); font-weight: 600; }}
  .domain-table td.fail {{ color: var(--red); font-weight: 600; }}
  .domain-table td.warn {{ color: var(--yellow); font-weight: 600; }}

  /* ── Findings Table ── */
  .findings-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 32px;
  }}
  .filter-bar {{
    display: flex;
    gap: 8px;
    padding: 12px 16px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }}
  .filter-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 12px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    cursor: pointer;
    transition: all 0.15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent);
    border-color: var(--accent);
    color: #000;
  }}
  .findings-table-wrap {{ overflow-x: auto; }}
  .findings-table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 1000px;
  }}
  .findings-table th {{
    background: var(--surface2);
    padding: 10px 14px;
    text-align: left;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  .findings-table td {{
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    vertical-align: top;
  }}
  .findings-table tr:last-child td {{ border-bottom: none; }}
  .findings-table tr:hover td {{ background: var(--surface2); }}
  .finding-row:hover td {{ background: var(--surface2); }}
  .detail-cell {{ max-width: 280px; font-size: 11px; color: var(--muted); line-height: 1.5; }}
  .affected-row {{ margin-top: 6px; font-size: 10px; color: var(--yellow); font-family: var(--mono); }}
  .affected-label {{ color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }}

  /* ── Evidence ── */
  .ev-toggle-cell {{ white-space: nowrap; }}
  .ev-toggle {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--accent);
    font-family: var(--mono);
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }}
  .ev-toggle:hover {{ background: var(--accent); color: #000; border-color: var(--accent); }}
  .ev-toggle.open {{ background: var(--accent); color: #000; }}
  .ev-none {{ color: var(--muted); font-family: var(--mono); font-size: 11px; }}
  .ev-row td {{ padding: 0 !important; background: #07090c !important; }}
  .ev-panel {{
    padding: 16px 20px;
    border-left: 2px solid var(--accent);
    margin: 0;
  }}
  .ev-block {{
    margin-bottom: 16px;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    background: var(--surface);
  }}
  .ev-block:last-child {{ margin-bottom: 0; }}
  .ev-cmd {{
    font-family: var(--mono);
    font-size: 12px;
    color: #e6edf3;
    padding: 8px 12px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    word-break: break-all;
  }}
  .ev-prompt {{ color: var(--accent2); font-weight: 700; margin-right: 6px; }}
  .ev-meta {{
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    padding: 5px 12px;
    border-bottom: 1px solid var(--border);
  }}
  .ev-file {{ color: var(--purple); }}
  .ev-out, .ev-err {{
    font-family: var(--mono);
    font-size: 11px;
    line-height: 1.5;
    margin: 0;
    padding: 10px 12px;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 320px;
    overflow: auto;
    color: var(--text);
  }}
  .ev-err {{ color: #ff7b72; border-top: 1px dashed var(--border); }}
  .ev-empty, .ev-none {{ color: var(--muted); font-size: 11px; font-style: italic; }}
  code {{
    font-family: var(--mono);
    font-size: 11px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 1px 5px;
    color: var(--accent);
  }}
  code.cid-ext {{ color: var(--purple); border-color: rgba(188,140,255,0.3); }}

  /* ── Badges ── */
  .status-badge, .sev-badge, .domain-badge {{
    display: inline-block;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.08em;
    border-radius: 3px;
    padding: 2px 7px;
    text-transform: uppercase;
    white-space: nowrap;
  }}
  .status-pass   {{ background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }}
  .status-fail   {{ background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }}
  .status-warn   {{ background: rgba(227,179,65,0.15); color: #e3b341; border: 1px solid rgba(227,179,65,0.3); }}
  .status-manual {{ background: rgba(188,140,255,0.15); color: #bc8cff; border: 1px solid rgba(188,140,255,0.3); }}
  .status-error  {{ background: rgba(110,118,129,0.15); color: #8b949e; border: 1px solid rgba(110,118,129,0.3); }}
  .sev-critical  {{ background: rgba(248,81,73,0.2); color: #ff7b72; border: 1px solid rgba(248,81,73,0.4); }}
  .sev-high      {{ background: rgba(210,153,34,0.15); color: #e3b341; border: 1px solid rgba(210,153,34,0.3); }}
  .sev-medium    {{ background: rgba(88,166,255,0.12); color: #79c0ff; border: 1px solid rgba(88,166,255,0.25); }}
  .sev-low       {{ background: rgba(63,185,80,0.1); color: #56d364; border: 1px solid rgba(63,185,80,0.2); }}
  .sev-info      {{ background: rgba(110,118,129,0.12); color: #8b949e; border: 1px solid rgba(110,118,129,0.25); }}
  .domain-badge  {{ background: var(--surface2); color: var(--muted); border: 1px solid var(--border); }}

  /* ── Footer ── */
  .footer {{
    border-top: 1px solid var(--border);
    padding: 20px 48px;
    text-align: center;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    max-width: 1400px;
    margin: 0 auto;
  }}
  .footer a {{ color: var(--accent); text-decoration: none; }}

  @media (max-width: 768px) {{
    .header, .main {{ padding: 20px; }}
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .header-grid {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-grid">
    <div>
      <div class="logo">URM Consulting — Security Assessment</div>
      <h1>Azure CIS Benchmark Report</h1>
      <div class="subtitle">CIS Microsoft Azure Foundations Benchmark v6.0.0</div>
      <div class="meta-pills">
        <div class="pill">Subscription: <span>{sub_name}</span></div>
        <div class="pill">ID: <span>{sub_id}</span></div>
        <div class="pill">Tenant: <span>{tenant_id}</span></div>
        <div class="pill">Generated: <span>{ts}</span></div>
        <div class="pill">Evidence captured: <span>{evidence_total} commands</span></div>
      </div>
    </div>
    <div class="score-widget">
      <div class="score-num">{score_pct}%</div>
      <div class="score-label">Pass Rate</div>
      <div class="score-bar"><div class="score-fill"></div></div>
    </div>
  </div>
</div>

<div class="main">

  <div class="stats-grid">
    <div class="stat-card c-total"><div class="stat-num">{total}</div><div class="stat-label">Total Checks</div></div>
    <div class="stat-card c-pass"><div class="stat-num">{passed}</div><div class="stat-label">Passed</div></div>
    <div class="stat-card c-fail"><div class="stat-num">{failed}</div><div class="stat-label">Failed</div></div>
    <div class="stat-card c-warn"><div class="stat-num">{warned}</div><div class="stat-label">Warnings</div></div>
    <div class="stat-card c-manual"><div class="stat-num">{manual}</div><div class="stat-label">Manual</div></div>
  </div>

  <div class="section-title">Domain Summary</div>
  <div class="domain-table-wrap">
    <table class="domain-table">
      <thead><tr><th>Domain</th><th>Total</th><th>Pass</th><th>Fail</th><th>Warn</th></tr></thead>
      <tbody>{domain_rows}</tbody>
    </table>
  </div>

  <div class="section-title">Findings</div>
  <div class="findings-wrap">
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterRows('ALL')">All</button>
      <button class="filter-btn" onclick="filterRows('PASS')">Pass</button>
      <button class="filter-btn" onclick="filterRows('FAIL')">Fail</button>
      <button class="filter-btn" onclick="filterRows('WARN')">Warn</button>
      <button class="filter-btn" onclick="filterRows('MANUAL')">Manual</button>
      <span style="flex:1"></span>
      <button class="filter-btn" onclick="toggleAllEv(true)">Expand evidence</button>
      <button class="filter-btn" onclick="toggleAllEv(false)">Collapse evidence</button>
    </div>
    <div class="findings-table-wrap">
      <table class="findings-table" id="findingsTable">
        <thead>
          <tr>
            <th>CIS ID</th>
            <th>Domain</th>
            <th>Check</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Detail</th>
            <th>Recommendation</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  <p>Azure CIS Benchmark Assessment &mdash; URM Consulting &mdash; <a href="https://www.cisecurity.org/benchmark/azure">CIS Azure Foundations Benchmark</a></p>
  <p style="margin-top:4px">Control IDs map to CIS Microsoft Azure Foundations Benchmark v6.0.0. IDs prefixed <code class="cid-ext">EXT-</code> are extended checks with no direct CIS control. <code>.x</code> denotes a section-level or Manual control.</p>
  <p style="margin-top:4px">This report is confidential and intended for authorised recipients only.</p>
</div>

<script>
function filterRows(status) {{
  const rows = document.querySelectorAll('#findingsTable tbody tr.finding-row');
  rows.forEach(row => {{
    const match = (status === 'ALL') || (row.getAttribute('data-status') === status);
    row.style.display = match ? '' : 'none';
    // keep paired evidence row in sync (collapse it when hiding)
    const evRow = row.nextElementSibling;
    if (evRow && evRow.classList.contains('ev-row')) {{
      if (!match) {{
        evRow.style.display = 'none';
        const btn = row.querySelector('.ev-toggle');
        if (btn) btn.classList.remove('open');
      }}
    }}
  }});
  document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
}}

function toggleEv(idx) {{
  const evRow = document.getElementById('ev-' + idx);
  if (!evRow) return;
  const btn = event.target;
  if (evRow.style.display === 'none' || !evRow.style.display) {{
    evRow.style.display = '';
    btn.classList.add('open');
    btn.textContent = btn.textContent.replace('▸', '▾');
  }} else {{
    evRow.style.display = 'none';
    btn.classList.remove('open');
    btn.textContent = btn.textContent.replace('▾', '▸');
  }}
}}

function toggleAllEv(open) {{
  document.querySelectorAll('.ev-row').forEach(r => {{
    const finding = r.previousElementSibling;
    if (finding && finding.style.display === 'none') return; // skip filtered-out
    r.style.display = open ? '' : 'none';
  }});
  document.querySelectorAll('.ev-toggle').forEach(b => {{
    if (open) {{ b.classList.add('open'); b.textContent = b.textContent.replace('▸','▾'); }}
    else {{ b.classList.remove('open'); b.textContent = b.textContent.replace('▾','▸'); }}
  }});
}}
</script>
</body>
</html>"""
print(html)
PYEOF

    rm -f "$findings_tmp"
    pass "HTML report: $HTML_FILE"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    banner

    # Setup
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$EVIDENCE_DIR"
    touch "$LOG_FILE"

    # Evidence state files (subshell-safe; see az_query / add_finding)
    EVIDENCE_SEQ_FILE="${OUTPUT_DIR}/.evidence_seq"
    EVIDENCE_BUF_FILE="${OUTPUT_DIR}/.evidence_buf"
    echo "0" > "$EVIDENCE_SEQ_FILE"
    : > "$EVIDENCE_BUF_FILE"

    log "Assessment started: $(date)"
    log "Output directory: $OUTPUT_DIR"

    check_deps

    # Verify auth
    log "Verifying Azure authentication..."
    local account
    account=$(az_query account show --query "user.name" -o tsv 2>/dev/null || echo "")
    if [[ -z "$account" ]]; then
        err "Not authenticated to Azure CLI. Run: az login"
        exit 1
    fi
    pass "Authenticated as: $account"
    log "Subscription: $(az_query account show --query 'name' -o tsv 2>/dev/null)"

    # Discard setup/auth evidence so it doesn't attach to the first finding
    evidence_reset

    # Run assessments
    assess_iam
    assess_defender
    assess_storage
    assess_sql
    assess_logging
    assess_networking
    assess_vms
    assess_keyvault
    assess_appservice
    assess_governance
    assess_entra_advanced
    assess_data_resources
    assess_other_data
    assess_containers

    # Generate reports
    echo -e "\n${BOLD}━━━ Generating Reports ━━━${RESET}"
    generate_json
    generate_html

    # Remove transient evidence state files (artifacts in evidence/ are kept)
    rm -f "$EVIDENCE_SEQ_FILE" "$EVIDENCE_BUF_FILE"

    # Summary
    echo -e "\n${CYAN}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║           Assessment Complete            ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"
    echo -e "  Total Checks : ${BOLD}$TOTAL${RESET}"
    echo -e "  ${GREEN}Passed${RESET}       : $PASS"
    echo -e "  ${RED}Failed${RESET}       : $FAIL"
    echo -e "  ${YELLOW}Warnings${RESET}     : $WARN"
    echo -e "  ${PURPLE}Manual${RESET}       : $MANUAL"
    echo -e ""
    echo -e "  📄 JSON   → ${BOLD}$JSON_FILE${RESET}"
    echo -e "  🌐 HTML   → ${BOLD}$HTML_FILE${RESET}"
    echo -e "  📋 Log    → ${BOLD}$LOG_FILE${RESET}"
    echo ""
    log "Assessment complete: $(date)"
}

main "$@"
