package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckModels_PrimaryMissing(t *testing.T) {
	cfg := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"openrouter": map[string]any{
					"models": []any{map[string]any{"id": "auto-beta"}},
				},
			},
		},
		"agents": map[string]any{
			"defaults": map[string]any{
				"model": map[string]any{
					"primary": "",
				},
			},
		},
	}
	findings := checkModels(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "MODEL_PRIMARY_MISSING" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected MODEL_PRIMARY_MISSING, got %v", findings)
	}
}

func TestCheckModels_HardcodedKey(t *testing.T) {
	cfg := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"bai": map[string]any{
					"baseUrl": "https://api.b.ai/v1",
					"apiKey":  "sk-8h0ei1dcstefiopvd94vn6muc44ku7k4-very-long-hardcoded",
					"models":  []any{map[string]any{"id": "m1"}},
				},
			},
		},
		"agents": map[string]any{
			"defaults": map[string]any{
				"model": map[string]any{"primary": "bai/m1"},
			},
		},
	}
	findings := checkProviders(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "PROVIDER_HARDCODED_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PROVIDER_HARDCODED_KEY, got %+v", findings)
	}
}

func TestCheckCronSchedules_InvalidExpr(t *testing.T) {
	cfg := map[string]any{
		"cron": map[string]any{
			"jobs": []any{
				map[string]any{
					"name":     "bad-cron",
					"schedule": map[string]any{"kind": "cron", "expr": "60 * * * *"},
				},
				map[string]any{
					"name":     "good-cron",
					"schedule": map[string]any{"kind": "cron", "expr": "0 9 * * *"},
				},
			},
		},
	}
	findings := checkCronSchedules(cfg, false)
	hasInvalid := false
	for _, f := range findings {
		if f.Subject == "bad-cron" && f.ID == "CRON_SCHEDULE_INVALID" {
			hasInvalid = true
		}
		if f.Subject == "good-cron" && f.ID == "CRON_SCHEDULE_INVALID" {
			t.Fatalf("good-cron should not be invalid")
		}
	}
	if !hasInvalid {
		t.Fatalf("expected CRON_SCHEDULE_INVALID for bad-cron, got %v", findings)
	}
}

func TestCheckStaleCrons(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cfg := map[string]any{
		"cron": map[string]any{
			"jobs": []any{
				map[string]any{
					"name":    "stale-job",
					"enabled": true,
					"schedule": map[string]any{
						"kind": "cron", "expr": "0 9 * * *",
					},
					"state": map[string]any{
						"lastRunAtMs":       float64(now.Add(-8 * 24 * time.Hour).UnixMilli()),
						"consecutiveErrors": float64(4),
						"lastError":         "timeout",
						"lastRunStatus":     "error",
					},
				},
				map[string]any{
					"name":    "fresh-job",
					"enabled": true,
					"schedule": map[string]any{
						"kind": "cron", "expr": "0 9 * * *",
					},
					"state": map[string]any{
						"lastRunAtMs":       float64(now.Add(-1 * time.Hour).UnixMilli()),
						"consecutiveErrors": float64(0),
						"lastRunStatus":     "ok",
					},
				},
			},
		},
	}
	findings := checkStaleCrons(cfg, "", now)
	var hasStale, hasConsec, hasFreshStale bool
	for _, f := range findings {
		if f.Subject == "stale-job" && f.ID == "CRON_STALE" {
			hasStale = true
		}
		if f.Subject == "stale-job" && f.ID == "CRON_CONSECUTIVE_ERRORS" {
			hasConsec = true
			if f.Severity != SeverityErr {
				t.Fatalf("expected ERROR for 4 consecutive errors, got %s", f.Severity)
			}
		}
		if f.Subject == "fresh-job" && f.ID == "CRON_STALE" {
			hasFreshStale = true
		}
	}
	if !hasStale {
		t.Fatalf("expected CRON_STALE for stale-job")
	}
	if !hasConsec {
		t.Fatalf("expected CRON_CONSECUTIVE_ERRORS for stale-job")
	}
	if hasFreshStale {
		t.Fatalf("fresh-job should not be stale")
	}
}

func TestCheckHeartbeat_IsolatedTilde(t *testing.T) {
	cfg := map[string]any{
		"cron": map[string]any{
			"jobs": []any{
				map[string]any{
					"name":          "my-cron",
					"sessionTarget": "isolated",
					"payload": map[string]any{
						"kind":    "agentTurn",
						"message": "Read ~/workspace/foo and ~/bar",
					},
					"schedule": map[string]any{"kind": "cron", "expr": "* * * * *"},
				},
			},
		},
	}
	findings := checkCronSchedules(cfg, false)
	found := false
	for _, f := range findings {
		if f.ID == "CRON_ISOLATED_TILDE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CRON_ISOLATED_TILDE, got %v", findings)
	}
}

func TestCheckProviders_EnvMissing(t *testing.T) {
	t.Setenv("CRON_DOCTOR_TEST_MISSING_VAR_XYZ", "")
	cfg := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"myprov": map[string]any{
					"baseUrl": "https://example.com",
					"apiKey": map[string]any{
						"source": "env",
						"id":     "CRON_DOCTOR_TEST_MISSING_VAR_XYZ",
					},
					"models": []any{map[string]any{"id": "m1"}},
				},
			},
		},
	}
	findings := checkProviders(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "PROVIDER_ENV_KEY_MISSING" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PROVIDER_ENV_KEY_MISSING, got %v", findings)
	}
}

func TestRunChecks_Integration(t *testing.T) {
	// Create temp openclaw.json
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "openclaw.json")
	cfg := map[string]any{
		"models": map[string]any{
			"providers": map[string]any{
				"openrouter": map[string]any{
					"baseUrl": "https://openrouter.ai/api/v1",
					"apiKey": map[string]any{
						"source": "env",
						"id":     "OPENROUTER_API_KEY_X_MISSING",
					},
					"models": []any{
						map[string]any{"id": "auto-beta"},
					},
				},
			},
		},
		"agents": map[string]any{
			"defaults": map[string]any{
				"model": map[string]any{
					"primary": "openrouter/auto-beta",
				},
				"heartbeat": map[string]any{
					"target":          "none",
					"isolatedSession": true,
				},
			},
		},
		"session": map[string]any{
			"dmScope": "per-channel-peer",
		},
		"cron": map[string]any{
			"maxConcurrentRuns": float64(8),
			"jobs": []any{
				map[string]any{
					"name":     "good",
					"enabled":  true,
					"schedule": map[string]any{"kind": "cron", "expr": "0 9 * * *"},
					"state": map[string]any{
						"lastRunAtMs":   float64(time.Now().Add(-1 * time.Hour).UnixMilli()),
						"lastRunStatus": "ok",
					},
					"payload": map[string]any{"kind": "agentTurn", "message": "hello"},
				},
			},
		},
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	findings := RunChecks(loaded, cfgPath, false, now)
	// Should have at least one finding (heartbeat isolated but none) + maybe provider env missing
	// Check no CRON_SCHEDULE_INVALID for good job
	for _, f := range findings {
		if f.ID == "CRON_SCHEDULE_INVALID" {
			t.Fatalf("unexpected invalid schedule: %+v", f)
		}
	}
	// JSON roundtrip via render
	var sb strings.Builder
	res := AuditResult{ConfigPath: cfgPath, Generated: now.Format(time.RFC3339), Findings: findings, Summary: buildSummary(findings)}
	if err := Render(res, FormatJSON, &sb); err != nil {
		t.Fatalf("render json: %v", err)
	}
	if !strings.Contains(sb.String(), "configPath") {
		t.Fatalf("json missing configPath")
	}
}

func TestDiscoverCronJobs_Empty(t *testing.T) {
	// Isolate HOME so host cron files don't pollute the test
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OPENCLAW_STATE_DIR", "")
	cfg := map[string]any{}
	jobs := discoverCronJobs(cfg)
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs, got %d", len(jobs))
	}
}

func TestCheckHeartbeat_NotIsolated(t *testing.T) {
	cfg := map[string]any{
		"agents": map[string]any{
			"defaults": map[string]any{
				"heartbeat": map[string]any{
					"target": "main",
					// isolatedSession missing => false
				},
			},
			"list": []any{
				map[string]any{
					"id": "main",
					"heartbeat": map[string]any{
						"every": "30m",
					},
				},
			},
		},
	}
	findings := checkHeartbeat(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "HEARTBEAT_NOT_ISOLATED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HEARTBEAT_NOT_ISOLATED, got %v", findings)
	}
}

func TestLoadConfig_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "cfg.json")
	content := `{"a": 1, "b": {"c": "hello"}}`
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if m["a"] != float64(1) {
		t.Fatalf("a mismatch")
	}
}
