# Sync Protection Rules

## Overview

The multi-agent-system repository receives one-directional syncs from the tmws
repository via the `scripts/sync-to-mas.sh` script in tmws. This sync copies
configuration files from tmws (source of truth) to multi-agent-system
(public distribution).

A sync protection mechanism prevents accidental rollback of intentional
changes made in multi-agent-system. This was introduced after an incident where
simplified agent definitions were overwritten by older detailed versions during
a routine sync.

## Incident Background

On 2026-01-29, commit `675aa98` synced from tmws and overwrote the Persona Forge
simplified agent definitions (commit `b5a43e3`, 2026-01-28) with old detailed
versions. The agent definition files grew from ~38 lines each to 100-200+ lines,
a 3-5x increase. This happened because:

1. The simplification was done in multi-agent-system first
2. The tmws source still had the old detailed versions at sync time
3. The sync script had no protection against such rollbacks

## Components

### `.syncprotect` (Repository Root)

Configuration file that defines:

- **`[thresholds]`** -- Size and line count ratios that trigger protection.
  Currently set to 1.5x, meaning any file growing more than 50% in a single
  sync is flagged.
- **`[protected]`** -- Glob patterns for files that must pass threshold
  validation. Currently protects agent definition files in both claude-code
  and open-code configs.
- **`[frozen]`** -- Glob patterns for files that must never be overwritten.
  Covers multi-agent-system-specific files like install scripts and docs.
- **`[options]`** -- Behavioral settings for the guard script.

### `scripts/sync-guard.sh`

Pre-sync validation script that reads `.syncprotect` and validates incoming
changes before they are applied. It runs in three phases:

1. **Frozen file check** -- Ensures no frozen files would be overwritten.
2. **Threshold check** -- Compares source and destination file sizes/line counts.
   Flags files that would grow beyond the configured ratio.
3. **Aggregate check** -- Ensures total line additions across all protected files
   stay within bounds.

## Usage

### Running the guard before sync

The `--source-root` and `--dest-root` flags accept repository root directories.
Patterns in `.syncprotect` are relative to these roots.

```bash
# From the multi-agent-system repository:
./scripts/sync-guard.sh \
  --source-root /path/to/tmws \
  --dest-root /path/to/multi-agent-system

# Dry run (check without blocking):
./scripts/sync-guard.sh \
  --source-root /path/to/tmws \
  --dest-root /path/to/multi-agent-system \
  --dry-run

# Verbose output (shows per-file comparisons):
./scripts/sync-guard.sh \
  --source-root /path/to/tmws \
  --dest-root /path/to/multi-agent-system \
  --verbose

# Force override (logs violations but does not block):
./scripts/sync-guard.sh \
  --source-root /path/to/tmws \
  --dest-root /path/to/multi-agent-system \
  --force
```

### Integration with tmws sync script

The tmws `scripts/sync-to-mas.sh` already integrates sync-guard. It calls
the guard automatically before each sync and supports these flags:

```bash
# Normal sync (guard runs automatically):
./scripts/sync-to-mas.sh

# Dry run (guard also runs in dry-run mode):
./scripts/sync-to-mas.sh --dry-run

# Force past protection (logs violations but proceeds):
./scripts/sync-to-mas.sh --force

# Skip guard entirely (not recommended):
./scripts/sync-to-mas.sh --skip-guard
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed, safe to sync |
| 1 | Script error (bad arguments, missing files) |
| 2 | Protection triggered, sync blocked |

## Threshold Tuning

The default thresholds are conservative. Adjust them in `.syncprotect`:

| Threshold | Default | Description |
|-----------|---------|-------------|
| `max_size_increase_ratio` | 1.5 | Max allowed size growth ratio |
| `max_line_increase_ratio` | 1.5 | Max allowed line count growth ratio |
| `min_size_for_ratio_check` | 100 | Files below this size skip ratio checks |
| `max_total_line_additions` | 200 | Max total line additions across all protected files |

### Why 1.5x?

The Persona Forge incident saw files grow 3-5x during rollback. A 1.5x
threshold catches rollbacks while still allowing legitimate additions (such
as adding a new section to an agent definition). Normal edits rarely exceed
50% growth in a single sync cycle.

## Backup Behavior

The guard creates timestamped backups of protected files in `.backups/` before
any sync operation. This provides a recovery path even if a sync is forced
through protection.

## Adding New Protection Rules

To protect a new file or pattern:

1. Edit `.syncprotect` in the repository root.
2. Add the glob pattern to `[protected]` (for threshold-checked files) or
   `[frozen]` (for files that must never be overwritten).
3. Commit the change.

Example -- protecting a new config directory:

```ini
[protected]
config/claude-code/agents/*.md
config/open-code/agent/*.md
config/new-platform/*.md     # Added protection
```

## Workflow for Intentional Large Changes

When a legitimate change needs to exceed thresholds (e.g., restructuring agent
definitions), follow this process:

1. Update the files in both tmws and multi-agent-system simultaneously.
2. Run sync-guard with `--dry-run` to verify the change would be flagged.
3. If flagged, temporarily adjust thresholds in `.syncprotect` or use `--force`.
4. After sync, restore the original thresholds.
5. Commit the threshold restoration.

Alternatively, make the change in tmws first, then sync. When both repositories
have the same content, the sync produces no diff and no protection is triggered.
