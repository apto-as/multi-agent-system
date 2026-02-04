#!/bin/bash
# =============================================================================
# Sync Guard - Pre-sync validation for multi-agent-system
# =============================================================================
# Validates incoming sync changes against .syncprotect rules before applying.
# Designed to prevent rollback incidents where simplified files get overwritten
# by older, detailed versions from the tmws source repository.
#
# Usage:
#   ./scripts/sync-guard.sh --source-root /path/to/tmws --dest-root /path/to/mas
#   ./scripts/sync-guard.sh --source-root /path/to/tmws --dest-root /path/to/mas --force
#   ./scripts/sync-guard.sh --source-root /path/to/tmws --dest-root /path/to/mas --dry-run
#
# The --source-root and --dest-root should point to the repository roots.
# Patterns in .syncprotect are relative to the repository root.
#
# Exit codes:
#   0 - All checks passed, safe to sync
#   1 - Script error (bad arguments, missing files)
#   2 - Protection triggered, sync blocked (configurable via .syncprotect)
# =============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SYNCPROTECT_FILE="$REPO_ROOT/.syncprotect"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
SOURCE_ROOT=""
DEST_ROOT=""
FORCE=false
DRY_RUN=false
VERBOSE=false
REPORT_FILE="$REPO_ROOT/.sync-report"

# Counters
TOTAL_CHECKED=0
TOTAL_BLOCKED=0
TOTAL_FROZEN_BLOCKED=0
TOTAL_WARNINGS=0

# --- Argument Parsing --------------------------------------------------------

usage() {
    echo "Usage: $0 --source-root <dir> --dest-root <dir> [options]"
    echo ""
    echo "Options:"
    echo "  --source-root <dir>  Source repository root (tmws)"
    echo "  --dest-root <dir>    Destination repository root (multi-agent-system)"
    echo "  --force              Override protection (still logs warnings)"
    echo "  --dry-run            Show what would be checked without blocking"
    echo "  --verbose            Show detailed comparison output"
    echo "  --report <file>      Custom report file path"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Patterns in .syncprotect are relative to repo root (e.g., config/claude-code/agents/*.md)."
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --source-root)
            SOURCE_ROOT="$2"
            shift 2
            ;;
        --dest-root)
            DEST_ROOT="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --report)
            REPORT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

if [[ -z "$SOURCE_ROOT" || -z "$DEST_ROOT" ]]; then
    echo -e "${RED}Error: --source-root and --dest-root are required${NC}"
    usage
fi

if [[ ! -d "$SOURCE_ROOT" ]]; then
    echo -e "${RED}Error: Source root not found: $SOURCE_ROOT${NC}"
    exit 1
fi

if [[ ! -d "$DEST_ROOT" ]]; then
    echo -e "${RED}Error: Destination root not found: $DEST_ROOT${NC}"
    exit 1
fi

# --- Config Parsing ----------------------------------------------------------

# Parse a value from .syncprotect INI-style config
# Usage: parse_config "section" "key" "default"
parse_config() {
    local section="$1"
    local key="$2"
    local default="${3:-}"

    if [[ ! -f "$SYNCPROTECT_FILE" ]]; then
        echo "$default"
        return
    fi

    local in_section=false
    local value=""

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        # Check for section header
        if [[ "$line" =~ ^\[([a-zA-Z_]+)\] ]]; then
            if [[ "${BASH_REMATCH[1]}" == "$section" ]]; then
                in_section=true
            else
                in_section=false
            fi
            continue
        fi

        # Parse key = value
        if $in_section && [[ "$line" =~ ^[[:space:]]*([a-zA-Z_]+)[[:space:]]*=[[:space:]]*(.*) ]]; then
            local parsed_key="${BASH_REMATCH[1]}"
            local parsed_value="${BASH_REMATCH[2]}"
            # Strip inline comments
            parsed_value="${parsed_value%%#*}"
            # Strip trailing whitespace
            parsed_value="$(echo -e "${parsed_value}" | sed -e 's/[[:space:]]*$//')"

            if [[ "$parsed_key" == "$key" ]]; then
                value="$parsed_value"
            fi
        fi
    done < "$SYNCPROTECT_FILE"

    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "$default"
    fi
}

# Parse a list of patterns from a section in .syncprotect
# Usage: parse_pattern_list "section"
parse_pattern_list() {
    local section="$1"
    local patterns=()

    if [[ ! -f "$SYNCPROTECT_FILE" ]]; then
        echo ""
        return
    fi

    local in_section=false

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        # Check for section header
        if [[ "$line" =~ ^\[([a-zA-Z_]+)\] ]]; then
            if [[ "${BASH_REMATCH[1]}" == "$section" ]]; then
                in_section=true
            else
                in_section=false
            fi
            continue
        fi

        # Collect patterns (lines that are not key=value)
        if $in_section && ! [[ "$line" =~ = ]]; then
            local pattern
            pattern="$(echo -e "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            if [[ -n "$pattern" ]]; then
                patterns+=("$pattern")
            fi
        fi
    done < "$SYNCPROTECT_FILE"

    if [[ ${#patterns[@]} -gt 0 ]]; then
        printf '%s\n' "${patterns[@]}"
    fi
}

# --- Load Configuration -----------------------------------------------------

MAX_SIZE_RATIO=$(parse_config "thresholds" "max_size_increase_ratio" "1.5")
MAX_LINE_RATIO=$(parse_config "thresholds" "max_line_increase_ratio" "1.5")
MIN_SIZE_FOR_CHECK=$(parse_config "thresholds" "min_size_for_ratio_check" "100")
MAX_TOTAL_ADDITIONS=$(parse_config "thresholds" "max_total_line_additions" "200")
REQUIRE_FORCE=$(parse_config "options" "require_force_for_override" "true")
GENERATE_REPORT=$(parse_config "options" "generate_report" "true")
BACKUP_PROTECTED=$(parse_config "options" "backup_protected_files" "true")
BLOCK_EXIT_CODE=$(parse_config "options" "block_exit_code" "2")

# Load patterns (compatible with macOS bash 3.x which lacks mapfile)
SYNC_SCOPE=()
while IFS= read -r line; do
    [[ -n "$line" ]] && SYNC_SCOPE+=("$line")
done < <(parse_pattern_list "sync_scope")

PROTECTED_PATTERNS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && PROTECTED_PATTERNS+=("$line")
done < <(parse_pattern_list "protected")

FROZEN_PATTERNS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && FROZEN_PATTERNS+=("$line")
done < <(parse_pattern_list "frozen")

# --- Utility Functions -------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_ok() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
    TOTAL_WARNINGS=$((TOTAL_WARNINGS + 1))
}

log_block() {
    echo -e "${RED}[BLOCK]${NC} $*"
    TOTAL_BLOCKED=$((TOTAL_BLOCKED + 1))
}

log_frozen() {
    echo -e "${RED}[FROZEN]${NC} $*"
    TOTAL_FROZEN_BLOCKED=$((TOTAL_FROZEN_BLOCKED + 1))
}

log_verbose() {
    if $VERBOSE; then
        echo -e "  ${NC}$*"
    fi
}

# Check if a file path matches any pattern in a list
# Usage: matches_pattern "file_path" "${patterns[@]}"
matches_pattern() {
    local file_path="$1"
    shift
    local patterns=("$@")

    for pattern in "${patterns[@]}"; do
        # Use bash glob matching (relative to repo root)
        # shellcheck disable=SC2254
        if [[ "$file_path" == $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Compare two numbers using bc for floating-point
# Usage: float_gt "1.6" "1.5" -> returns 0 if true
float_gt() {
    local result
    result=$(echo "$1 > $2" | bc -l 2>/dev/null || echo "0")
    [[ "$result" == "1" ]]
}

float_div() {
    echo "scale=2; $1 / $2" | bc -l 2>/dev/null || echo "0"
}

# --- Core Validation ---------------------------------------------------------

# Validate a single file against thresholds
# Returns 0 if OK, 1 if blocked
validate_file() {
    local rel_path="$1"
    local src_file="$SOURCE_ROOT/$rel_path"
    local dst_file="$DEST_ROOT/$rel_path"

    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    # If destination file does not exist, this is a new file - always allow
    if [[ ! -f "$dst_file" ]]; then
        log_verbose "New file (no existing version): $rel_path"
        return 0
    fi

    # If source file does not exist, this would be a deletion - always allow
    if [[ ! -f "$src_file" ]]; then
        log_verbose "Deletion (source missing): $rel_path"
        return 0
    fi

    local src_size dst_size src_lines dst_lines
    src_size=$(wc -c < "$src_file" | tr -d ' ')
    dst_size=$(wc -c < "$dst_file" | tr -d ' ')
    src_lines=$(wc -l < "$src_file" | tr -d ' ')
    dst_lines=$(wc -l < "$dst_file" | tr -d ' ')

    log_verbose "$rel_path: current=${dst_lines}L/${dst_size}B -> incoming=${src_lines}L/${src_size}B"

    # Skip ratio check if destination is too small
    if [[ "$dst_size" -lt "$MIN_SIZE_FOR_CHECK" ]]; then
        log_verbose "Skipping ratio check (file too small: ${dst_size}B < ${MIN_SIZE_FOR_CHECK}B)"
        return 0
    fi

    local size_ratio="1.00"
    local line_ratio="1.00"

    # Check size increase ratio
    if [[ "$dst_size" -gt 0 ]]; then
        size_ratio=$(float_div "$src_size" "$dst_size")

        if float_gt "$size_ratio" "$MAX_SIZE_RATIO"; then
            log_block "$rel_path: size would increase ${size_ratio}x (${dst_size}B -> ${src_size}B, limit: ${MAX_SIZE_RATIO}x)"
            return 1
        fi
    fi

    # Check line count increase ratio
    if [[ "$dst_lines" -gt 0 ]]; then
        line_ratio=$(float_div "$src_lines" "$dst_lines")

        if float_gt "$line_ratio" "$MAX_LINE_RATIO"; then
            log_block "$rel_path: line count would increase ${line_ratio}x (${dst_lines}L -> ${src_lines}L, limit: ${MAX_LINE_RATIO}x)"
            return 1
        fi
    fi

    log_ok "$rel_path (size: ${size_ratio}x, lines: ${line_ratio}x)"
    return 0
}

# Check if a file is frozen (must not be overwritten)
check_frozen() {
    local rel_path="$1"
    local src_file="$SOURCE_ROOT/$rel_path"

    # Only relevant if the source has a file that would land at a frozen path
    if [[ ! -f "$src_file" ]]; then
        return 0
    fi

    if [[ ${#FROZEN_PATTERNS[@]} -eq 0 ]]; then
        return 0
    fi

    if matches_pattern "$rel_path" "${FROZEN_PATTERNS[@]}"; then
        log_frozen "$rel_path: file is frozen and must not be overwritten by sync"
        return 1
    fi

    return 0
}

# --- Report Generation -------------------------------------------------------

generate_sync_report() {
    local status="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$REPORT_FILE" << REPORT_EOF
# Sync Guard Report
# Generated: $timestamp

## Summary
- Status: $status
- Files checked: $TOTAL_CHECKED
- Files blocked: $TOTAL_BLOCKED
- Frozen violations: $TOTAL_FROZEN_BLOCKED
- Warnings: $TOTAL_WARNINGS
- Force mode: $FORCE
- Dry run: $DRY_RUN

## Configuration
- Max size increase ratio: ${MAX_SIZE_RATIO}x
- Max line increase ratio: ${MAX_LINE_RATIO}x
- Min size for ratio check: ${MIN_SIZE_FOR_CHECK}B
- Max total line additions: $MAX_TOTAL_ADDITIONS

## Source
- Source root: $SOURCE_ROOT
- Destination root: $DEST_ROOT
- Syncprotect: $SYNCPROTECT_FILE
REPORT_EOF
}

# --- Backup Protected Files --------------------------------------------------

backup_protected() {
    if [[ "$BACKUP_PROTECTED" != "true" ]] || $DRY_RUN; then
        return
    fi

    local backup_dir="$REPO_ROOT/.backups/sync-guard-$(date +%Y%m%d-%H%M%S)"
    local backed_up=0

    for pattern in "${PROTECTED_PATTERNS[@]}"; do
        # Find files matching the pattern relative to DEST_ROOT
        while IFS= read -r -d '' file; do
            local rel_path="${file#"$DEST_ROOT/"}"
            local backup_path="$backup_dir/$rel_path"
            mkdir -p "$(dirname "$backup_path")"
            cp "$file" "$backup_path"
            backed_up=$((backed_up + 1))
        done < <(find "$DEST_ROOT" -path "$DEST_ROOT/$pattern" -type f -print0 2>/dev/null)
    done

    if [[ $backed_up -gt 0 ]]; then
        log_info "Backed up $backed_up protected files to $backup_dir"
    fi
}

# --- Main Execution ----------------------------------------------------------

main() {
    echo -e "${BOLD}=== Sync Guard ===${NC}"
    echo -e "Source root:  $SOURCE_ROOT"
    echo -e "Dest root:    $DEST_ROOT"
    echo -e "Config:       $SYNCPROTECT_FILE"
    echo ""

    if [[ ! -f "$SYNCPROTECT_FILE" ]]; then
        log_warn "No .syncprotect file found at $SYNCPROTECT_FILE"
        log_warn "All files will pass validation (no protection rules defined)"
        exit 0
    fi

    log_info "Sync scope: ${SYNC_SCOPE[*]:-all}"
    log_info "Protected patterns: ${PROTECTED_PATTERNS[*]:-none}"
    log_info "Frozen patterns: ${FROZEN_PATTERNS[*]:-none}"
    log_info "Thresholds: size=${MAX_SIZE_RATIO}x, lines=${MAX_LINE_RATIO}x, total_additions=${MAX_TOTAL_ADDITIONS}"

    if $FORCE; then
        log_warn "Force mode enabled - protection violations will be logged but not block sync"
    fi

    if $DRY_RUN; then
        log_info "Dry run mode - no changes will be made"
    fi

    echo ""

    # --- Phase 1: Frozen file checks ---
    echo -e "${BOLD}Phase 1: Frozen file check${NC}"

    local frozen_violations=0

    if [[ ${#FROZEN_PATTERNS[@]} -eq 0 ]]; then
        log_ok "No frozen patterns defined (skipping)"
    else
        # For frozen check, we enumerate source files within sync scope and see
        # if they would land on a frozen path in the destination.
        if [[ ${#SYNC_SCOPE[@]} -gt 0 ]]; then
            for scope_dir in "${SYNC_SCOPE[@]}"; do
                if [[ -d "$SOURCE_ROOT/$scope_dir" ]]; then
                    while IFS= read -r -d '' src_file; do
                        local rel_path="${src_file#"$SOURCE_ROOT/"}"
                        if ! check_frozen "$rel_path"; then
                            frozen_violations=$((frozen_violations + 1))
                        fi
                    done < <(find "$SOURCE_ROOT/$scope_dir" -type f -print0 2>/dev/null)
                fi
            done
        else
            # No sync scope defined - check all source files
            while IFS= read -r -d '' src_file; do
                local rel_path="${src_file#"$SOURCE_ROOT/"}"
                if ! check_frozen "$rel_path"; then
                    frozen_violations=$((frozen_violations + 1))
                fi
            done < <(find "$SOURCE_ROOT" -type f -print0 2>/dev/null)
        fi
    fi

    if [[ $frozen_violations -eq 0 ]]; then
        log_ok "No frozen file violations"
    else
        log_warn "$frozen_violations frozen file(s) would be overwritten"
    fi

    echo ""

    # --- Phase 2: Protected file threshold checks ---
    echo -e "${BOLD}Phase 2: Protected file threshold check${NC}"

    local threshold_violations=0
    local total_line_additions=0

    for pattern in "${PROTECTED_PATTERNS[@]}"; do
        log_verbose "Checking pattern: $pattern"

        # Find matching files in the source repository
        while IFS= read -r -d '' src_file; do
            local rel_path="${src_file#"$SOURCE_ROOT/"}"
            local dst_file="$DEST_ROOT/$rel_path"

            log_verbose "Found source file: $rel_path"

            if [[ -f "$dst_file" ]]; then
                if ! validate_file "$rel_path"; then
                    threshold_violations=$((threshold_violations + 1))
                fi

                # Track total line additions
                local src_lines dst_lines
                src_lines=$(wc -l < "$src_file" | tr -d ' ')
                dst_lines=$(wc -l < "$dst_file" | tr -d ' ')
                local diff=$((src_lines - dst_lines))
                if [[ $diff -gt 0 ]]; then
                    total_line_additions=$((total_line_additions + diff))
                fi
            else
                log_verbose "No existing destination file for $rel_path (new file, allowed)"
            fi
        done < <(find "$SOURCE_ROOT" -path "$SOURCE_ROOT/$pattern" -type f -print0 2>/dev/null)
    done

    # Check aggregate line additions
    if [[ $total_line_additions -gt $MAX_TOTAL_ADDITIONS ]]; then
        log_block "Total line additions across protected files: ${total_line_additions} (limit: ${MAX_TOTAL_ADDITIONS})"
        threshold_violations=$((threshold_violations + 1))
    else
        log_ok "Total line additions: ${total_line_additions} (limit: ${MAX_TOTAL_ADDITIONS})"
    fi

    echo ""

    # --- Phase 3: Summary and decision ---
    echo -e "${BOLD}=== Sync Guard Summary ===${NC}"

    local total_violations=$((frozen_violations + threshold_violations))

    echo -e "Files checked:       $TOTAL_CHECKED"
    echo -e "Threshold blocks:    $threshold_violations"
    echo -e "Frozen violations:   $frozen_violations"
    echo -e "Total violations:    $total_violations"
    echo -e "Warnings:            $TOTAL_WARNINGS"
    echo ""

    # Backup protected files before reporting final decision
    if [[ $total_violations -eq 0 ]]; then
        backup_protected
    fi

    # Generate report
    if [[ "$GENERATE_REPORT" == "true" ]]; then
        if [[ $total_violations -gt 0 ]]; then
            generate_sync_report "BLOCKED"
        else
            generate_sync_report "PASSED"
        fi
        log_info "Report written to $REPORT_FILE"
    fi

    # Final decision
    if [[ $total_violations -gt 0 ]]; then
        if $FORCE; then
            echo -e "${YELLOW}${BOLD}SYNC PROTECTION OVERRIDDEN (--force)${NC}"
            echo -e "${YELLOW}$total_violations violation(s) logged but sync will proceed${NC}"
            backup_protected
            exit 0
        elif $DRY_RUN; then
            echo -e "${YELLOW}${BOLD}SYNC WOULD BE BLOCKED${NC}"
            echo -e "${YELLOW}$total_violations violation(s) detected in dry run${NC}"
            exit 0
        else
            echo -e "${RED}${BOLD}SYNC BLOCKED${NC}"
            echo -e "${RED}$total_violations violation(s) detected. Sync will not proceed.${NC}"
            echo ""
            echo -e "To investigate, run with --verbose for detailed output."
            echo -e "To override, run with --force (not recommended)."
            echo -e "To update protection rules, edit .syncprotect in the repository root."
            exit "$BLOCK_EXIT_CODE"
        fi
    else
        echo -e "${GREEN}${BOLD}ALL CHECKS PASSED${NC}"
        echo -e "${GREEN}Safe to proceed with sync.${NC}"
        exit 0
    fi
}

main
