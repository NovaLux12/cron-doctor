package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	var (
		configPath = flag.String("config", "", "path to openclaw.json (default: ~/.openclaw/openclaw.json)")
		format     = flag.String("format", "table", "output format: table|json|markdown")
		failOn     = flag.String("fail-on", "error", "exit non-zero when findings at or above this level: error|warn|info|never")
		verbose    = flag.Bool("verbose", false, "include OK findings")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "cron-doctor %s — audit OpenClaw cron/heartbeat health\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nChecks:\n")
		fmt.Fprintf(os.Stderr, "  cron schedule validity (cron expr + every/at), model exists,\n")
		fmt.Fprintf(os.Stderr, "  heartbeat isolatedSession vs dmScope, provider health,\n")
		fmt.Fprintf(os.Stderr, "  stale crons (>7d), delivery failures from proactivity/log.md\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  cron-doctor --format json | jq .\n")
		fmt.Fprintf(os.Stderr, "  cron-doctor --config ~/.openclaw/openclaw.json --fail-on warn\n")
		fmt.Fprintf(os.Stderr, "  cron-doctor --verbose --format markdown > audit.md\n")
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("cron-doctor %s\n", version)
		os.Exit(0)
	}

	formatNorm := strings.ToLower(strings.TrimSpace(*format))
	if formatNorm != FormatTable && formatNorm != FormatJSON && formatNorm != FormatMarkdown {
		fmt.Fprintf(os.Stderr, "error: --format must be table|json|markdown, got %q\n", *format)
		os.Exit(2)
	}
	failNorm := strings.ToLower(strings.TrimSpace(*failOn))
	switch failNorm {
	case "error", "warn", "info", "never", "":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "error: --fail-on must be error|warn|info|never, got %q\n", *failOn)
		os.Exit(2)
	}
	if failNorm == "" {
		failNorm = "error"
	}

	cfgPath, err := ResolveConfigPath(*configPath)
	if err != nil {
		// still warn but try to continue if explicit path given
		if *configPath != "" {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "warning: %v (continuing with empty config path)\n", err)
		}
	}
	cfg := map[string]any{}
	if cfgPath != "" {
		if _, statErr := os.Stat(cfgPath); statErr == nil {
			loaded, loadErr := LoadConfig(cfgPath)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "error: failed to load config %s: %v\n", cfgPath, loadErr)
				os.Exit(2)
			}
			cfg = loaded
		} else {
			if *configPath != "" {
				fmt.Fprintf(os.Stderr, "error: config not found: %s\n", cfgPath)
				os.Exit(2)
			}
			// no config found, run with empty cfg (provider checks will warn)
			fmt.Fprintf(os.Stderr, "warning: config not found at %s — running with empty config (some checks will be skipped)\n", cfgPath)
			cfg = map[string]any{}
		}
	}

	now := time.Now().UTC()
	findings := RunChecks(cfg, cfgPath, *verbose, now)

	// Filter OK if not verbose
	if !*verbose {
		// Keep OK only if it's the ALL_OK sentinel? Actually RunChecks may return OK sentinel
		// If there are non-OK findings, drop OK ones.
		hasNonOK := false
		for _, f := range findings {
			if f.Severity != SeverityOK {
				hasNonOK = true
				break
			}
		}
		if hasNonOK {
			filtered := findings[:0]
			for _, f := range findings {
				if f.Severity != SeverityOK {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}
	}

	summary := buildSummary(findings)
	result := AuditResult{
		ConfigPath: cfgPath,
		Generated:  now.Format(time.RFC3339),
		Findings:   findings,
		Summary:    summary,
	}
	if err := Render(result, formatNorm, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "render error: %v\n", err)
		os.Exit(2)
	}

	// Exit code based on --fail-on
	exit := 0
	switch failNorm {
	case "never":
		exit = 0
	case "error":
		if summary.Error > 0 {
			exit = 1
		}
	case "warn":
		if summary.Error > 0 || summary.Warn > 0 {
			exit = 1
		}
	case "info":
		if summary.Error > 0 || summary.Warn > 0 || summary.Info > 0 {
			exit = 1
		}
	}
	os.Exit(exit)
}
