package main

import (
	"strings"
	"testing"
	"time"
)

func TestRender_Table(t *testing.T) {
	res := AuditResult{
		ConfigPath: "/tmp/openclaw.json",
		Generated:  time.Now().Format(time.RFC3339),
		Findings: []Finding{
			{ID: "PROVIDER_HARDCODED_KEY", Severity: SeverityErr, Category: "provider", Subject: "bai", Message: "hardcoded key"},
			{ID: "CRON_STALE", Severity: SeverityWarn, Category: "cron", Subject: "my-cron", Message: "stale 10 days"},
		},
	}
	res.Summary = buildSummary(res.Findings)
	var sb strings.Builder
	if err := Render(res, FormatTable, &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "cron-doctor audit") {
		t.Fatalf("missing header")
	}
	if !strings.Contains(out, "PROVIDER") && !strings.Contains(out, "provider") {
		// category column
		if !strings.Contains(out, "bai") {
			t.Fatalf("missing bai subject")
		}
	}
}

func TestRender_JSONAndMarkdown(t *testing.T) {
	res := AuditResult{
		ConfigPath: "/tmp/cfg.json",
		Generated:  time.Now().Format(time.RFC3339),
		Findings: []Finding{
			{ID: "MODEL_UNKNOWN", Severity: SeverityWarn, Category: "model", Subject: "foo/bar", Message: "unknown model", Hint: "check list"},
		},
	}
	res.Summary = buildSummary(res.Findings)
	var sb strings.Builder
	if err := Render(res, FormatJSON, &sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "MODEL_UNKNOWN") {
		t.Fatalf("json missing id")
	}
	sb.Reset()
	if err := Render(res, FormatMarkdown, &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.Contains(out, "| Severity |") {
		t.Fatalf("markdown missing table header")
	}
	if !strings.Contains(out, "MODEL_UNKNOWN") {
		// ID not in columns but severity/message should be there
		if !strings.Contains(out, "unknown model") {
			t.Fatalf("markdown missing message")
		}
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	res := AuditResult{}
	var sb strings.Builder
	if err := Render(res, "yaml", &sb); err == nil {
		t.Fatalf("expected error for unknown format")
	}
}

func TestBuildSummary(t *testing.T) {
	f := []Finding{
		{Severity: SeverityErr},
		{Severity: SeverityWarn},
		{Severity: SeverityWarn},
		{Severity: SeverityInfo},
		{Severity: SeverityOK},
	}
	s := buildSummary(f)
	if s.Error != 1 || s.Warn != 2 || s.Info != 1 || s.OK != 1 || s.Total != 5 {
		t.Fatalf("summary mismatch: %+v", s)
	}
}

func TestResolveConfigPath_Explicit(t *testing.T) {
	p, err := ResolveConfigPath("/tmp/myconfig.json")
	if err != nil {
		t.Fatal(err)
	}
	if p != "/tmp/myconfig.json" {
		t.Fatalf("got %s", p)
	}
}
