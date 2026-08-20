package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Severity levels
const (
	SeverityOK   = "OK"
	SeverityWarn = "WARN"
	SeverityErr  = "ERROR"
	SeverityInfo = "INFO"
)

// Finding is one audit result.

// Finding is one audit result.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

// AuditResult holds all findings.
type AuditResult struct {
	ConfigPath string    `json:"configPath"`
	Generated  string    `json:"generatedAt"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

// Summary counts per severity.
type Summary struct {
	Total int `json:"total"`
	OK    int `json:"ok"`
	Warn  int `json:"warn"`
	Error int `json:"error"`
	Info  int `json:"info"`
}

// OpenClawConfig minimal struct for checks we care about.
type OpenClawConfig struct {
	Raw map[string]any `json:"-"`
}

// LoadConfig reads and parses openclaw.json.
func LoadConfig(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// ResolveConfigPath resolves --config or default candidates.
func ResolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	// Order: explicit env, then common locations
	candidates := []string{
		filepath.Join(os.Getenv("HOME"), ".openclaw", "openclaw.json"),
		filepath.Join(os.Getenv("HOME"), ".openclaw", "workspace", "openclaw.json"),
		"openclaw.json",
		"./openclaw.json",
	}
	if v := os.Getenv("OPENCLAW_CONFIG_PATH"); v != "" {
		candidates = append([]string{v}, candidates...)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return candidates[0], fmt.Errorf("no config found; tried %s", strings.Join(candidates, ", "))
}

// RunChecks executes all audits.
func RunChecks(cfg map[string]any, cfgPath string, verbose bool, now time.Time) []Finding {
	var findings []Finding

	// 1. cron schedule validity
	findings = append(findings, checkCronSchedules(cfg, verbose)...)

	// 2. model exists
	findings = append(findings, checkModels(cfg)...)

	// 3. heartbeat vs dmScope
	findings = append(findings, checkHeartbeat(cfg)...)

	// 4. provider health
	findings = append(findings, checkProviders(cfg)...)

	// 5. stale crons
	findings = append(findings, checkStaleCrons(cfg, cfgPath, now)...)

	// 6. delivery failures from proactivity/log.md
	findings = append(findings, checkDeliveryFailures(cfg, cfgPath)...)

	// 7. general config sanity (bonus)
	findings = append(findings, checkGeneral(cfg)...)

	if len(findings) == 0 {
		findings = append(findings, Finding{
			ID:       "ALL_OK",
			Severity: SeverityOK,
			Category: "general",
			Subject:  "config",
			Message:  "No issues detected",
		})
	}
	return findings
}

// Helpers to get nested maps safely.

func getMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if mm, ok := v.(map[string]any); ok {
			return mm
		}
	}
	return nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// --- checks ---

func checkCronSchedules(cfg map[string]any, verbose bool) []Finding {
	// Cron jobs are not stored in openclaw.json's cron field (only maxConcurrentRuns).
	// Try to discover jobs file; if not found, validate only what we have.
	// Also check for any schedule-like fields elsewhere.

	var findings []Finding

	// If cfg contains cron.jobs array (future format) validate those.
	cronSection := getMap(cfg, "cron")
	if cronSection != nil {
		if jobs, ok := cronSection["jobs"]; ok {
			if arr, ok := jobs.([]any); ok {
				for i, j := range arr {
					m, ok := j.(map[string]any)
					if !ok {
						continue
					}
					name := getString(m, "name")
					if name == "" {
						name = fmt.Sprintf("cron[%d]", i)
					}
					sched := getMap(m, "schedule")
					if err := ValidateSchedule(sched); err != nil {
						findings = append(findings, Finding{
							ID:       "CRON_SCHEDULE_INVALID",
							Severity: SeverityErr,
							Category: "cron",
							Subject:  name,
							Message:  err.Error(),
							Hint:     "Fix expr or switch kind to every/at; see crontab(5)",
						})
					} else if verbose {
						findings = append(findings, Finding{
							ID:       "CRON_SCHEDULE_OK",
							Severity: SeverityOK,
							Category: "cron",
							Subject:  name,
							Message:  "schedule valid",
						})
					}
				}
			}
		}
		// Validate maxConcurrentRuns
		if v, ok := cronSection["maxConcurrentRuns"]; ok {
			var n float64
			switch x := v.(type) {
			case float64:
				n = x
			case int:
				n = float64(x)
			}
			if n < 1 || n > 64 {
				findings = append(findings, Finding{
					ID:       "CRON_CONCURRENCY_RANGE",
					Severity: SeverityWarn,
					Category: "cron",
					Subject:  "cron.maxConcurrentRuns",
					Message:  fmt.Sprintf("value %v outside recommended [1,64]", v),
					Hint:     "Set between 1 and 32 for most hosts",
				})
			}
		}
	}

	// Try to load external jobs file for deeper validation
	jobs := discoverCronJobs(cfg)
	for _, job := range jobs {
		sched := getMap(job, "schedule")
		name := getString(job, "name")
		if name == "" {
			name = getString(job, "id")
		}
		if name == "" {
			name = "unknown-job"
		}
		if err := ValidateSchedule(sched); err != nil {
			findings = append(findings, Finding{
				ID:       "CRON_SCHEDULE_INVALID",
				Severity: SeverityErr,
				Category: "cron",
				Subject:  name,
				Message:  err.Error(),
				Hint:     "Run: openclaw cron edit <id> --schedule <expr>",
			})
		}
		// Check payload
		payload := getMap(job, "payload")
		if payload != nil {
			kind := getString(payload, "kind")
			if kind == "agentTurn" {
				msg := getString(payload, "message")
				if msg == "" {
					findings = append(findings, Finding{
						ID:       "CRON_EMPTY_PAYLOAD",
						Severity: SeverityWarn,
						Category: "cron",
						Subject:  name,
						Message:  "agentTurn payload has empty message",
						Hint:     "Add a prompt or switch to command kind",
					})
				}
				// check for absolute path issues when isolated
				target := getString(job, "sessionTarget")
				if target == "isolated" && strings.Contains(msg, "~/") {
					findings = append(findings, Finding{
						ID:       "CRON_ISOLATED_TILDE",
						Severity: SeverityWarn,
						Category: "cron",
						Subject:  name,
						Message:  "isolated cron message contains ~/ — will not expand (use an absolute path like /home/user/...)",
						Hint:     "Replace ~ with absolute path; isolated sessions start at /",
					})
				}
			}
		}
	}

	if len(jobs) == 0 && len(findings) == 0 && verbose {
		findings = append(findings, Finding{
			ID:       "CRON_NO_JOBS",
			Severity: SeverityInfo,
			Category: "cron",
			Subject:  "cron",
			Message:  "No cron jobs discovered to validate (config has no jobs array and no jobs file found)",
			Hint:     "Run: openclaw cron list --json to verify gateway jobs",
		})
	}
	return findings
}

func checkModels(cfg map[string]any) []Finding {
	var findings []Finding

	// Build known model set from models.providers
	modelsSection := getMap(cfg, "models")
	providers := getMap(modelsSection, "providers")
	known := map[string]bool{}
	for _, pv := range providers {
		pm, ok := pv.(map[string]any)
		if !ok {
			continue
		}
		if arr, ok := pm["models"].([]any); ok {
			for _, mm := range arr {
				if m, ok := mm.(map[string]any); ok {
					id := getString(m, "id")
					if id != "" {
						known[id] = true
						// also allow provider/id form
						// provider key added later
					}
				}
			}
		}
	}
	// Also collect provider/id combos
	for prov, pv := range providers {
		pm, ok := pv.(map[string]any)
		if !ok {
			continue
		}
		if arr, ok := pm["models"].([]any); ok {
			for _, mm := range arr {
				if m, ok := mm.(map[string]any); ok {
					id := getString(m, "id")
					if id != "" {
						known[prov+"/"+id] = true
					}
				}
			}
		}
	}

	agents := getMap(cfg, "agents")
	defaults := getMap(agents, "defaults")
	modelCfg := getMap(defaults, "model")
	primary := getString(modelCfg, "primary")
	if primary == "" {
		findings = append(findings, Finding{
			ID:       "MODEL_PRIMARY_MISSING",
			Severity: SeverityWarn,
			Category: "model",
			Subject:  "agents.defaults.model.primary",
			Message:  "primary model not set",
			Hint:     "Set to e.g. openrouter/auto-beta or stepfun/step-3.7-flash",
		})
	} else {
		if !known[primary] {
			// also check if prefix matches a provider
			parts := strings.SplitN(primary, "/", 2)
			if len(parts) == 2 {
				if _, ok := providers[parts[0]]; !ok {
					findings = append(findings, Finding{
						ID:       "MODEL_PROVIDER_UNKNOWN",
						Severity: SeverityErr,
						Category: "model",
						Subject:  primary,
						Message:  fmt.Sprintf("provider %q not in models.providers", parts[0]),
						Hint:     "Add provider to models.providers or fix typo",
					})
				} else {
					findings = append(findings, Finding{
						ID:       "MODEL_UNKNOWN",
						Severity: SeverityWarn,
						Category: "model",
						Subject:  primary,
						Message:  fmt.Sprintf("model %q not found in known models", primary),
						Hint:     "Check models.providers[].models[].id list",
					})
				}
			} else {
				findings = append(findings, Finding{
					ID:       "MODEL_UNKNOWN",
					Severity: SeverityWarn,
					Category: "model",
					Subject:  primary,
					Message:  fmt.Sprintf("model %q not found in known models", primary),
					Hint:     "Use provider/model format",
				})
			}
		}
	}
	// Fallbacks
	if fb, ok := modelCfg["fallbacks"]; ok {
		if arr, ok := fb.([]any); ok {
			for _, f := range arr {
				s, _ := f.(string)
				if s == "" {
					continue
				}
				if !known[s] {
					parts := strings.SplitN(s, "/", 2)
					if len(parts) == 2 {
						if _, ok := providers[parts[0]]; !ok {
							findings = append(findings, Finding{
								ID:       "MODEL_FALLBACK_PROVIDER_UNKNOWN",
								Severity: SeverityWarn,
								Category: "model",
								Subject:  s,
								Message:  fmt.Sprintf("fallback provider %q unknown", parts[0]),
							})
						} else {
							findings = append(findings, Finding{
								ID:       "MODEL_FALLBACK_UNKNOWN",
								Severity: SeverityInfo,
								Category: "model",
								Subject:  s,
								Message:  fmt.Sprintf("fallback model %q not in known list", s),
								Hint:     "May be valid if provider supports it; verify",
							})
						}
					}
				}
			}
			// same-provider fallback useless check
			if primary != "" && len(arr) > 0 {
				priProv := strings.SplitN(primary, "/", 2)[0]
				for _, f := range arr {
					s, _ := f.(string)
					fbProv := strings.SplitN(s, "/", 2)[0]
					if fbProv == priProv {
						findings = append(findings, Finding{
							ID:       "MODEL_SAME_PROVIDER_FALLBACK",
							Severity: SeverityInfo,
							Category: "model",
							Subject:  s,
							Message:  fmt.Sprintf("fallback %q shares provider %q with primary — won't help if provider is down", s, priProv),
							Hint:     "Use cross-provider fallbacks for resilience",
						})
						break
					}
				}
			}
		}
	}
	// Check agents.list entries for model overrides
	if al, ok := agents["list"]; ok {
		if arr, ok := al.([]any); ok {
			for _, a := range arr {
				m, ok := a.(map[string]any)
				if !ok {
					continue
				}
				id := getString(m, "id")
				am := getMap(m, "model")
				if am == nil {
					continue
				}
				pri := getString(am, "primary")
				if pri != "" && !known[pri] {
					findings = append(findings, Finding{
						ID:       "MODEL_AGENT_UNKNOWN",
						Severity: SeverityWarn,
						Category: "model",
						Subject:  fmt.Sprintf("agents.list[%s].model.primary", id),
						Message:  fmt.Sprintf("model %q not in known list", pri),
					})
				}
			}
		}
	}
	return findings
}

func checkHeartbeat(cfg map[string]any) []Finding {
	var findings []Finding
	agents := getMap(cfg, "agents")
	defaults := getMap(agents, "defaults")
	hb := getMap(defaults, "heartbeat")
	session := getMap(cfg, "session")
	dmScope := getString(session, "dmScope")

	target := getString(hb, "target")
	isolatedSess := false
	if v, ok := hb["isolatedSession"]; ok {
		if b, ok := v.(bool); ok {
			isolatedSess = b
		}
	}
	// Check target vs isolatedSession consistency
	if target == "none" && isolatedSess {
		findings = append(findings, Finding{
			ID:       "HEARTBEAT_ISOLATED_BUT_NONE",
			Severity: SeverityInfo,
			Category: "heartbeat",
			Subject:  "agents.defaults.heartbeat",
			Message:  "isolatedSession true but target is none (heartbeat disabled) — isolated flag has no effect",
			Hint:     "Either set target to an agent or set isolatedSession false",
		})
	}
	// dmScope check: per-channel-peer with isolatedSession false is ok; but isolated true with shared scope warns
	if dmScope == "per-channel-peer" && isolatedSess {
		// not necessarily wrong but worth noting
		findings = append(findings, Finding{
			ID:       "HEARTBEAT_ISOLATED_DM_SCOPE",
			Severity: SeverityInfo,
			Category: "heartbeat",
			Subject:  "session.dmScope",
			Message:  "dmScope per-channel-peer with isolatedSession true — isolated heartbeat will not share DM context",
			Hint:     "If heartbeat needs DM history, consider isolatedSession false",
		})
	}
	// Check per-agent heartbeat overrides
	if al, ok := agents["list"]; ok {
		if arr, ok := al.([]any); ok {
			for _, a := range arr {
				m, ok := a.(map[string]any)
				if !ok {
					continue
				}
				id := getString(m, "id")
				ahb := getMap(m, "heartbeat")
				if ahb == nil {
					continue
				}
				every := getString(ahb, "every")
				if every == "0m" || every == "0" {
					// disabled
					continue
				}
				// If agent has heartbeat.every set but isolatedSession missing, flag
				// Heartbeats should generally use isolated sessions to avoid polluting main
				if _, ok := ahb["isolatedSession"]; !ok {
					// inherit from defaults?
					if !isolatedSess {
						findings = append(findings, Finding{
							ID:       "HEARTBEAT_NOT_ISOLATED",
							Severity: SeverityWarn,
							Category: "heartbeat",
							Subject:  fmt.Sprintf("agents.list[%s].heartbeat", id),
							Message:  "heartbeat enabled but isolatedSession not set — heartbeat turns share main session state",
							Hint:     "Set heartbeat.isolatedSession true unless you need shared context",
						})
					}
				}
			}
		}
	}
	// heartbeat interval sanity: check if heartbeat file exists
	return findings
}

func checkProviders(cfg map[string]any) []Finding {
	var findings []Finding
	modelsSection := getMap(cfg, "models")
	providers := getMap(modelsSection, "providers")
	if providers == nil || len(providers) == 0 {
		findings = append(findings, Finding{
			ID:       "PROVIDER_NONE",
			Severity: SeverityWarn,
			Category: "provider",
			Subject:  "models.providers",
			Message:  "no providers configured",
			Hint:     "Add at least one provider with baseUrl and apiKey",
		})
		return findings
	}
	for prov, pv := range providers {
		pm, ok := pv.(map[string]any)
		if !ok {
			findings = append(findings, Finding{
				ID:       "PROVIDER_MALFORMED",
				Severity: SeverityErr,
				Category: "provider",
				Subject:  prov,
				Message:  "provider entry is not an object",
			})
			continue
		}
		base := getString(pm, "baseUrl")
		if base == "" {
			findings = append(findings, Finding{
				ID:       "PROVIDER_NO_BASEURL",
				Severity: SeverityErr,
				Category: "provider",
				Subject:  prov,
				Message:  "baseUrl missing",
			})
		} else if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
			findings = append(findings, Finding{
				ID:       "PROVIDER_BASEURL_SCHEME",
				Severity: SeverityWarn,
				Category: "provider",
				Subject:  prov,
				Message:  fmt.Sprintf("baseUrl %q should start with https://", base),
			})
		}
		// apiKey checks
		if ak, ok := pm["apiKey"]; ok {
			switch v := ak.(type) {
			case string:
				if strings.HasPrefix(v, "sk-") && len(v) > 20 {
					findings = append(findings, Finding{
						ID:       "PROVIDER_HARDCODED_KEY",
						Severity: SeverityErr,
						Category: "provider",
						Subject:  prov,
						Message:  "apiKey contains hardcoded secret — use env or exec source",
						Hint:     "Change to {\"source\":\"env\",\"id\":\"PROVIDER_API_KEY\"}",
					})
				}
			case map[string]any:
				src := getString(v, "source")
				if src == "env" {
					id := getString(v, "id")
					if id == "" {
						findings = append(findings, Finding{
							ID:       "PROVIDER_ENV_KEY_NO_ID",
							Severity: SeverityWarn,
							Category: "provider",
							Subject:  prov,
							Message:  "apiKey source env but id empty",
						})
					} else if os.Getenv(id) == "" {
						findings = append(findings, Finding{
							ID:       "PROVIDER_ENV_KEY_MISSING",
							Severity: SeverityWarn,
							Category: "provider",
							Subject:  prov,
							Message:  fmt.Sprintf("env var %s not set (provider %s may fail)", id, prov),
							Hint:     fmt.Sprintf("export %s=... or check provider auth", id),
						})
					}
				} else if src == "exec" {
					cmd := getString(v, "command")
					providerRef := getString(v, "provider")
					if cmd == "" {
						if providerRef != "" {
							secrets := getMap(cfg, "secrets")
							secProviders := getMap(secrets, "providers")
							if secProviders == nil {
								findings = append(findings, Finding{
									ID:       "PROVIDER_EXEC_NO_CMD",
									Severity: SeverityErr,
									Category: "provider",
									Subject:  prov,
									Message:  fmt.Sprintf("apiKey exec source references provider %q but secrets.providers missing", providerRef),
								})
							} else if _, ok := secProviders[providerRef]; !ok {
								findings = append(findings, Finding{
									ID:       "PROVIDER_EXEC_NO_CMD",
									Severity: SeverityErr,
									Category: "provider",
									Subject:  prov,
									Message:  fmt.Sprintf("apiKey exec source references provider %q not in secrets.providers", providerRef),
								})
							}
						} else {
							findings = append(findings, Finding{
								ID:       "PROVIDER_EXEC_NO_CMD",
								Severity: SeverityErr,
								Category: "provider",
								Subject:  prov,
								Message:  "apiKey exec source missing command (and no provider reference)",
							})
						}
					}
				}
			}
		} else {
			if base != "" && !strings.Contains(base, "localhost") && !strings.Contains(base, "127.0.0.1") {
				findings = append(findings, Finding{
					ID:       "PROVIDER_NO_APIKEY",
					Severity: SeverityWarn,
					Category: "provider",
					Subject:  prov,
					Message:  "no apiKey configured for non-local provider",
				})
			}
		}
		// models check
		if arr, ok := pm["models"].([]any); ok {
			if len(arr) == 0 {
				findings = append(findings, Finding{
					ID:       "PROVIDER_NO_MODELS",
					Severity: SeverityWarn,
					Category: "provider",
					Subject:  prov,
					Message:  "provider has no models listed",
					Hint:     "Add models[] or remove provider if unused",
				})
			}
			seen := map[string]bool{}
			for _, mm := range arr {
				mmMap, ok := mm.(map[string]any)
				if !ok {
					continue
				}
				id := getString(mmMap, "id")
				if id == "" {
					findings = append(findings, Finding{
						ID:       "PROVIDER_MODEL_NO_ID",
						Severity: SeverityWarn,
						Category: "provider",
						Subject:  prov,
						Message:  "model entry missing id",
					})
					continue
				}
				if seen[id] {
					findings = append(findings, Finding{
						ID:       "PROVIDER_MODEL_DUPLICATE",
						Severity: SeverityWarn,
						Category: "provider",
						Subject:  prov + "/" + id,
						Message:  fmt.Sprintf("duplicate model id %q in provider %q", id, prov),
					})
				}
				seen[id] = true
			}
		}
	}
	return findings
}

func checkStaleCrons(cfg map[string]any, cfgPath string, now time.Time) []Finding {
	var findings []Finding
	jobs := discoverCronJobs(cfg)
	if len(jobs) == 0 {
		return findings
	}
	for _, job := range jobs {
		name := getString(job, "name")
		if name == "" {
			name = getString(job, "id")
		}
		if name == "" {
			name = "unknown"
		}
		enabled, _ := job["enabled"].(bool)
		// Check disabled crons that were expected to run
		if !enabled {
			findings = append(findings, Finding{
				ID:       "CRON_DISABLED",
				Severity: SeverityInfo,
				Category: "cron",
				Subject:  name,
				Message:  "cron is disabled",
			})
			continue
		}
		state := getMap(job, "state")
		if state == nil {
			// No state, check createdAt
			createdMs, _ := job["createdAtMs"].(float64)
			if createdMs > 0 {
				created := time.UnixMilli(int64(createdMs))
				if now.Sub(created) > 7*24*time.Hour {
					findings = append(findings, Finding{
						ID:       "CRON_NO_STATE",
						Severity: SeverityWarn,
						Category: "cron",
						Subject:  name,
						Message:  fmt.Sprintf("no state after %d days — may never have run", int(now.Sub(created).Hours()/24)),
						Hint:     "Check gateway logs; run: openclaw cron run <id>",
					})
				}
			}
			continue
		}
		lastRunMs, ok := state["lastRunAtMs"].(float64)
		if !ok || lastRunMs == 0 {
			// Try top-level lastRunAtMs
			lastRunMs, _ = job["lastRunAtMs"].(float64)
		}
		if lastRunMs == 0 {
			findings = append(findings, Finding{
				ID:       "CRON_NEVER_RUN",
				Severity: SeverityWarn,
				Category: "cron",
				Subject:  name,
				Message:  "never run (lastRunAtMs is zero)",
				Hint:     "If cron is new this is ok; otherwise check: openclaw cron list",
			})
			continue
		}
		lastRun := time.UnixMilli(int64(lastRunMs))
		age := now.Sub(lastRun)
		if age > 7*24*time.Hour {
			days := int(age.Hours() / 24)
			findings = append(findings, Finding{
				ID:       "CRON_STALE",
				Severity: SeverityWarn,
				Category: "cron",
				Subject:  name,
				Message:  fmt.Sprintf("last run %d days ago (%s)", days, lastRun.Format(time.RFC3339)),
				Hint:     "Cron may be stuck or disabled at gateway; check openclaw cron list",
			})
		}
		// consecutiveErrors
		if ce, ok := state["consecutiveErrors"].(float64); ok && ce > 0 {
			msg := fmt.Sprintf("%d consecutive errors", int(ce))
			sev := SeverityWarn
			if ce >= 3 {
				sev = SeverityErr
			}
			lastErr := ""
			if s, ok := state["lastError"].(string); ok {
				lastErr = s
			} else if s, ok := state["lastRunError"].(string); ok {
				lastErr = s
			}
			if lastErr != "" {
				msg += fmt.Sprintf(": %s", lastErr)
			}
			findings = append(findings, Finding{
				ID:       "CRON_CONSECUTIVE_ERRORS",
				Severity: sev,
				Category: "cron",
				Subject:  name,
				Message:  msg,
				Hint:     "Check logs: openclaw cron list --json | jq .",
			})
		}
		// lastRunStatus error
		if s, ok := state["lastRunStatus"].(string); ok && s == "error" {
			// already covered by consecutiveErrors, but add if no consecutiveErrors field
			if _, has := state["consecutiveErrors"]; !has {
				findings = append(findings, Finding{
					ID:       "CRON_LAST_RUN_ERROR",
					Severity: SeverityWarn,
					Category: "cron",
					Subject:  name,
					Message:  "last run status is error",
				})
			}
		}
	}
	return findings
}

func checkDeliveryFailures(cfg map[string]any, cfgPath string) []Finding {
	var findings []Finding
	// Locate proactivity/log.md relative to config or workspace
	candidates := []string{}
	home := os.Getenv("HOME")
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".openclaw", "workspace", "proactivity", "log.md"),
			filepath.Join(home, ".openclaw", "workspace", "proactivity", "stale-strikes.md"),
		)
	}
	// Also try relative to config path
	if cfgPath != "" {
		dir := filepath.Dir(cfgPath)
		candidates = append(candidates,
			filepath.Join(dir, "proactivity", "log.md"),
			filepath.Join(dir, "..", "proactivity", "log.md"),
			filepath.Join(dir, "workspace", "proactivity", "log.md"),
		)
	}
	// Also memory/proactivity if workspace is nested
	seen := map[string]bool{}
	for _, p := range candidates {
		if seen[p] {
			continue
		}
		seen[p] = true
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		content := string(b)
		// Look for failure patterns
		lines := strings.Split(content, "\n")
		reFail := regexp.MustCompile(`(?i)(fail|error|exception|delivery.*fail|consecutiveErrors|stale|blocked)`)
		count := 0
		var examples []string
		for _, l := range lines {
			if reFail.MatchString(l) {
				count++
				if len(examples) < 3 {
					trim := strings.TrimSpace(l)
					if len(trim) > 120 {
						trim = trim[:120] + "…"
					}
					examples = append(examples, trim)
				}
			}
		}
		if count > 0 {
			// Check if mostly old entries — look for recent dates
			// Count occurrences of 2026-08 in failures vs older
			recentFail := 0
			for _, l := range lines {
				if reFail.MatchString(l) && strings.Contains(l, "2026-08") {
					recentFail++
				}
			}
			sev := SeverityInfo
			msg := fmt.Sprintf("%d potential failure/error mentions in %s", count, p)
			if recentFail > 0 {
				sev = SeverityWarn
				msg = fmt.Sprintf("%d failure mentions (%d in Aug 2026) in %s", count, recentFail, p)
			}
			if len(examples) > 0 {
				msg += fmt.Sprintf(" e.g. %q", examples[0])
			}
			findings = append(findings, Finding{
				ID:       "DELIVERY_LOG_HITS",
				Severity: sev,
				Category: "delivery",
				Subject:  p,
				Message:  msg,
				Hint:     "Review log for real delivery failures vs historical notes",
			})
		}
		// Also check for cron failure in log.md table rows
		if strings.Contains(p, "log.md") && strings.Contains(content, "consecutiveErrors") {
			findings = append(findings, Finding{
				ID:       "DELIVERY_CRON_ERRORS_IN_LOG",
				Severity: SeverityWarn,
				Category: "delivery",
				Subject:  p,
				Message:  "log.md references consecutiveErrors — some crons may have delivery issues",
			})
		}
		// Only report first found log.md
		break
	}
	// Also check delivery queue warning from gateway if available via config? not applicable
	return findings
}

func checkGeneral(cfg map[string]any) []Finding {
	var findings []Finding
	// Check gateway auth
	gw := getMap(cfg, "gateway")
	if gw != nil {
		auth := getMap(gw, "auth")
		if auth != nil {
			if tok := getString(auth, "token"); tok != "" && len(tok) < 10 {
				findings = append(findings, Finding{
					ID:       "GATEWAY_TOKEN_WEAK",
					Severity: SeverityWarn,
					Category: "gateway",
					Subject:  "gateway.auth.token",
					Message:  "gateway token looks too short",
				})
			}
		}
	}
	// Check for deprecated/minimal config
	if cfg["agents"] == nil {
		findings = append(findings, Finding{
			ID:       "CONFIG_NO_AGENTS",
			Severity: SeverityWarn,
			Category: "general",
			Subject:  "agents",
			Message:  "agents section missing",
		})
	}
	return findings
}

// discoverCronJobs attempts to find cron jobs from various locations.
func discoverCronJobs(cfg map[string]any) []map[string]any {
	// First check if config itself has jobs (for testing)
	if cronSection := getMap(cfg, "cron"); cronSection != nil {
		if jobs, ok := cronSection["jobs"].([]any); ok && len(jobs) > 0 {
			var out []map[string]any
			for _, j := range jobs {
				if m, ok := j.(map[string]any); ok {
					out = append(out, m)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}

	// Try filesystem locations
	home := os.Getenv("HOME")
	candidates := []string{}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".openclaw", "cron", "jobs.json"),
			filepath.Join(home, ".openclaw", "cron", "jobs.json.migrated"),
			filepath.Join(home, ".openclaw", "workspace", "cron.json"),
		)
	}
	// Also respect OPENCLAW_STATE_DIR
	if s := os.Getenv("OPENCLAW_STATE_DIR"); s != "" {
		candidates = append([]string{filepath.Join(s, "cron", "jobs.json")}, candidates...)
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var data any
		if err := json.Unmarshal(b, &data); err != nil {
			continue
		}
		// Handle both {jobs: [...]} and direct [...]
		var arr []any
		switch v := data.(type) {
		case map[string]any:
			if j, ok := v["jobs"].([]any); ok {
				arr = j
			}
		case []any:
			arr = v
		}
		var out []map[string]any
		for _, j := range arr {
			if m, ok := j.(map[string]any); ok {
				out = append(out, m)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}
