# cron-doctor

[![CI](https://github.com/NovaLux12/cron-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaLux12/cron-doctor/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/NovaLux12/cron-doctor)](https://github.com/NovaLux12/cron-doctor/releases) [![Go version](https://img.shields.io/github/go-mod/go-version/NovaLux12/cron-doctor)](https://go.dev/) [![License: MIT](https://img.shields.io/github/license/NovaLux12/cron-doctor)](LICENSE)

Single-binary CLI that audits OpenClaw cron and heartbeat health. Reads your `openclaw.json`, validates cron schedules, checks models/providers, flags stale jobs and delivery anomalies. Zero dependencies, stdlib only, builds to a static binary.
## Install

### Via go install (requires Go 1.22+)

```bash
go install github.com/NovaLux12/cron-doctor@latest
```

### From source

```bash
git clone https://github.com/NovaLux12/cron-doctor
cd cron-doctor
go build -o cron-doctor .
# optional
sudo install -m 0755 cron-doctor /usr/local/bin/cron-doctor
```

Requires Go 1.22+. No runtime dependencies — stdlib only, static binary.

### Quick run without installing

```bash
go run . --help
```

## Usage

```
cron-doctor --help
```

```
Flags:
  --config string   path to openclaw.json (default: ~/.openclaw/openclaw.json)
  --format string   output format: table|json|markdown (default "table")
  --fail-on string  exit non-zero when findings at or above this level: error|warn|info|never (default "error")
  --verbose         include OK findings
  --version         print version and exit
```
### Examples

```bash
# Table (human) output against default config location
cron-doctor

# JSON for scripting
cron-doctor --format json | jq '.summary'

# Markdown report
cron-doctor --format markdown > audit.md

# Strict CI gate — fail on warnings too
cron-doctor --fail-on warn

# Audit a specific file verbosely
cron-doctor --config /tmp/openclaw.json --verbose --format table

# Never fail (report only)
cron-doctor --fail-on never --format json
```

### Exit codes

| `--fail-on` | Exits 1 when… |
|-------------|---------------|
| `error` (default) | any `ERROR` finding |
| `warn` | any `ERROR` or `WARN` |
| `info` | any `ERROR`, `WARN`, or `INFO` |
| `never` | never (always 0 unless usage error) |

Usage errors exit 2.

## What it checks

| Category | ID | Severity | Description |
|----------|----|----------|-------------|
| `cron` | `CRON_SCHEDULE_INVALID` | ERROR | `schedule.expr` fails 5-field cron validation (or bad `everyMs`/`at`) |
| `cron` | `CRON_EMPTY_PAYLOAD` | WARN | `agentTurn` with empty message |
| `cron` | `CRON_ISOLATED_TILDE` | WARN | Isolated cron message contains `~/` (won't expand; use absolute path) |
| `cron` | `CRON_CONCURRENCY_RANGE` | WARN | `cron.maxConcurrentRuns` outside [1,64] |
| `cron` | `CRON_STALE` | WARN | Last run >7 days ago |
| `cron` | `CRON_NEVER_RUN` / `CRON_NO_STATE` | WARN | No run history |
| `cron` | `CRON_CONSECUTIVE_ERRORS` | WARN/ERROR | `consecutiveErrors >0` (ERROR if ≥3) |
| `cron` | `CRON_DISABLED` | INFO | Job is disabled |
| `model` | `MODEL_PRIMARY_MISSING` | WARN | No primary model |
| `model` | `MODEL_UNKNOWN` / `MODEL_PROVIDER_UNKNOWN` | WARN/ERROR | Primary model not in `models.providers` |
| `model` | `MODEL_FALLBACK_*` | INFO/WARN | Fallback issues; `MODEL_SAME_PROVIDER_FALLBACK` when fallback shares provider with primary |
| `heartbeat` | `HEARTBEAT_ISOLATED_BUT_NONE` | INFO | `isolatedSession true` but `target none` |
| `heartbeat` | `HEARTBEAT_NOT_ISOLATED` | WARN | Heartbeat enabled without isolation |
| `provider` | `PROVIDER_HARDCODED_KEY` | ERROR | Raw `sk-` key in config (use `env`/`exec` source) |
| `provider` | `PROVIDER_ENV_KEY_MISSING` | WARN | Referenced env var not set |
| `provider` | `PROVIDER_NO_BASEURL` etc. | ERROR/WARN | Provider shape issues, duplicate model ids |
| `delivery` | `DELIVERY_LOG_HITS` | INFO/WARN | `proactivity/log.md` contains failure-like lines |
| `gateway` | `GATEWAY_TOKEN_WEAK` | WARN | Short gateway token |

### Cron expression rules

5-field POSIX cron: `minute hour dom month dow`

- `*`, `*/n`, `a-b`, `a,b`, `a-b/n` in each field
- Ranges validated against field bounds (minute 0-59, hour 0-23, dom 1-31, month 1-12, dow 0-7)
- Month/DOW names allowed (`JAN`–`DEC`, `MON`–`SUN`)
- Shortcuts: `@annually`, `@yearly`, `@monthly`, `@weekly`, `@daily`, `@midnight`, `@hourly`, `@reboot`
- Timezone `tz` validated via `time.LoadLocation`
- `kind: every` requires `everyMs > 60000`; `kind: at` requires RFC3339 timestamp

### Where it looks for cron jobs

`openclaw.json` itself rarely contains jobs (only `cron.maxConcurrentRuns`). `cron-doctor` also tries:

- `~/.openclaw/cron/jobs.json`
- `~/.openclaw/cron/jobs.json.migrated`
- `~/.openclaw/workspace/cron.json`
- `$OPENCLAW_STATE_DIR/cron/jobs.json`

If none exist, schedule checks run against `cron.jobs` inside the config if present (useful for testing).

### Proactivity log

Looks for `~/.openclaw/workspace/proactivity/log.md` (and variants relative to `--config`) and counts lines matching `fail|error|exception|delivery.*fail|stale|blocked`. Recent (August 2026) hits are escalated to `WARN`.

## Output formats

- **table** — human-readable with icons (✗/⚠/·/✓), hints, and PASS/WARN/FAIL footer
- **json** — `{configPath, generatedAt, findings[], summary{total,error,warn,info,ok}}` for `jq`/CI
- **markdown** — GitHub-friendly table with hints

## Testing

```bash
go vet ./...
go test ./...
go build -o cron-doctor .
./cron-doctor --help
```

## Design

- `main.go` — flag parsing, orchestration, exit-code policy
- `check.go` — all audits + `discoverCronJobs` + config resolution
- `cron.go` — 5-field cron + `every`/`at` validation, no external deps
- `render.go` — table/json/markdown renderers

## Related

- [fleet-pulse](https://github.com/NovaLux12/fleet-pulse) — unified fleet health pulse (stale pushes, Dependabot, CI, release gaps) — same stdlib-only, single-binary philosophy. Uses `GH_TOKEN` / `GITHUB_TOKEN` for GitHub API access.
- [gh-digest](https://github.com/NovaLux12/gh-digest) — per-owner repo digest (issues, PRs, releases) — the original companion tool. Also uses `GH_TOKEN` / `GITHUB_TOKEN`.

> **Note:** `cron-doctor` is local-only and needs no GitHub token. `fleet-pulse` and `gh-digest` read the GitHub API and respect `GH_TOKEN` (preferred) with `GITHUB_TOKEN` fallback — set either for 5000 req/h (vs 60/h unauthenticated).

## License

MIT — see [LICENSE](LICENSE).
