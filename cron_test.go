package main

import "testing"

func TestValidateCronExpr_Valid(t *testing.T) {
	valid := []string{
		"* * * * *",
		"0 9 * * *",
		"30 0 * * *",
		"0 2 * * *",
		"*/5 * * * *",
		"0 9-17 * * MON-FRI",
		"0 0 1 * *",
		"0 0 * * 0",
		"15 3 * * 1,3,5",
		"0 9 1 JAN *",
		"0 6 * * SUN",
		"@daily",
		"@hourly",
		"@weekly",
		"@monthly",
		"@annually",
		"@reboot",
	}
	for _, expr := range valid {
		if err := ValidateCronExpr(expr); err != nil {
			t.Errorf("expected valid %q, got error: %v", expr, err)
		}
	}
}

func TestValidateCronExpr_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"* * * *",
		"* * * * * *",
		"60 * * * *",
		"* 24 * * *",
		"* * 32 * *",
		"* * * 13 *",
		"*/0 * * * *",
		"5-2 * * * *",
		"@unknown",
		"not a cron",
		"0 9 * * MON-FOO",
	}
	for _, expr := range invalid {
		if err := ValidateCronExpr(expr); err == nil {
			t.Errorf("expected invalid %q to error", expr)
		}
	}
}

func TestValidateSchedule(t *testing.T) {
	tests := []struct {
		name    string
		sched   map[string]any
		wantErr bool
	}{
		{"valid cron", map[string]any{"kind": "cron", "expr": "30 6 * * *"}, false},
		{"invalid cron expr", map[string]any{"kind": "cron", "expr": "60 * * * *"}, true},
		{"missing expr", map[string]any{"kind": "cron"}, true},
		{"bad tz", map[string]any{"kind": "cron", "expr": "* * * * *", "tz": "Not/Real"}, true},
		{"good tz", map[string]any{"kind": "cron", "expr": "* * * * *", "tz": "Europe/London"}, false},
		{"every valid", map[string]any{"kind": "every", "everyMs": float64(3600000)}, false},
		{"every too small", map[string]any{"kind": "every", "everyMs": float64(1000)}, true},
		{"every zero", map[string]any{"kind": "every", "everyMs": float64(0)}, true},
		{"at valid", map[string]any{"kind": "at", "at": "2026-10-02T08:00:00.000Z"}, false},
		{"at invalid", map[string]any{"kind": "at", "at": "not-a-time"}, true},
		{"unknown kind", map[string]any{"kind": "bogus"}, true},
		{"nil sched", nil, true},
	}
	for _, tc := range tests {
		err := ValidateSchedule(tc.sched)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: wantErr=%v got err=%v", tc.name, tc.wantErr, err)
		}
	}
}

func TestValidateCronExpr_StepAndRange(t *testing.T) {
	// */15 valid
	if err := ValidateCronExpr("*/15 * * * *"); err != nil {
		t.Fatalf("*/15: %v", err)
	}
	// 0-30/5 valid
	if err := ValidateCronExpr("0-30/5 * * * *"); err != nil {
		t.Fatalf("0-30/5: %v", err)
	}
	// 0/15 valid? Actually 0/15 is weird but we treat base as value
	// Our parser: item "0/15" -> base "0" range check ok, step 15
	if err := ValidateCronExpr("0/15 * * * *"); err != nil {
		t.Fatalf("0/15: %v", err)
	}
}
