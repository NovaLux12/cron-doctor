package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Format constants
const (
	FormatTable    = "table"
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
)

func Render(result AuditResult, format string, w io.Writer) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(result)
	case FormatMarkdown:
		return renderMarkdown(result, w)
	case FormatTable, "":
		return renderTable(result, w)
	default:
		return fmt.Errorf("unknown format %q: use table|json|markdown", format)
	}
}

func renderTable(result AuditResult, w io.Writer) error {
	fmt.Fprintln(w, "cron-doctor audit")
	fmt.Fprintln(w, strings.Repeat("─", 60))
	fmt.Fprintf(w, "Config: %s\n", result.ConfigPath)
	fmt.Fprintf(w, "Generated: %s\n", result.Generated)
	fmt.Fprintf(w, "Summary: %d findings — %d ERROR, %d WARN, %d INFO, %d OK\n",
		result.Summary.Total, result.Summary.Error, result.Summary.Warn, result.Summary.Info, result.Summary.OK)
	fmt.Fprintln(w, strings.Repeat("─", 60))
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "No findings")
		return nil
	}
	// Determine column widths
	sevW, catW, subjW := 7, 10, 20
	for _, f := range result.Findings {
		if len(f.Severity) > sevW {
			sevW = len(f.Severity)
		}
		if len(f.Category) > catW {
			catW = len(f.Category)
		}
		if len(f.Subject) > subjW {
			subjW = len(f.Subject)
			if subjW > 32 {
				subjW = 32
			}
		}
	}
	header := fmt.Sprintf("%-*s  %-*s  %-*s  %s", sevW, "SEVERITY", catW, "CATEGORY", subjW, "SUBJECT", "MESSAGE")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("─", len(header)+20))
	for _, f := range result.Findings {
		icon := severityIcon(f.Severity)
		subj := f.Subject
		if len(subj) > 32 {
			subj = subj[:29] + "..."
		}
		line := fmt.Sprintf("%s %-*s  %-*s  %-*s  %s", icon, sevW, f.Severity, catW, f.Category, subjW, subj, f.Message)
		fmt.Fprintln(w, line)
		if f.Hint != "" {
			fmt.Fprintf(w, "%*s↳ %s\n", sevW+2, "", f.Hint)
		}
	}
	fmt.Fprintln(w, strings.Repeat("─", 60))
	// Exit hint
	if result.Summary.Error > 0 {
		fmt.Fprintln(w, "Result: FAIL (errors found)")
	} else if result.Summary.Warn > 0 {
		fmt.Fprintln(w, "Result: WARN (warnings found)")
	} else {
		fmt.Fprintln(w, "Result: PASS")
	}
	return nil
}

func renderMarkdown(result AuditResult, w io.Writer) error {
	fmt.Fprintln(w, "# cron-doctor audit")
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "- **Config:** `%s`\n", result.ConfigPath)
	fmt.Fprintf(w, "- **Generated:** %s\n", result.Generated)
	fmt.Fprintf(w, "- **Summary:** %d findings — %d ERROR · %d WARN · %d INFO · %d OK\n",
		result.Summary.Total, result.Summary.Error, result.Summary.Warn, result.Summary.Info, result.Summary.OK)
	fmt.Fprintln(w, "")
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}
	fmt.Fprintln(w, "| Severity | Category | Subject | Message |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range result.Findings {
		icon := severityIcon(f.Severity)
		msg := strings.ReplaceAll(f.Message, "|", "\\|")
		subj := strings.ReplaceAll(f.Subject, "|", "\\|")
		fmt.Fprintf(w, "| %s %s | %s | `%s` | %s |\n", icon, f.Severity, f.Category, subj, msg)
		if f.Hint != "" {
			fmt.Fprintf(w, "|  |  |  | _Hint: %s_ |\n", strings.ReplaceAll(f.Hint, "|", "\\|"))
		}
	}
	fmt.Fprintln(w, "")
	if result.Summary.Error > 0 {
		fmt.Fprintln(w, "**Result: FAIL**")
	} else if result.Summary.Warn > 0 {
		fmt.Fprintln(w, "**Result: WARN**")
	} else {
		fmt.Fprintln(w, "**Result: PASS**")
	}
	return nil
}

func severityIcon(s string) string {
	switch s {
	case SeverityErr:
		return "✗"
	case SeverityWarn:
		return "⚠"
	case SeverityOK:
		return "✓"
	case SeverityInfo:
		return "·"
	default:
		return " "
	}
}

func buildSummary(findings []Finding) Summary {
	var s Summary
	s.Total = len(findings)
	for _, f := range findings {
		switch f.Severity {
		case SeverityErr:
			s.Error++
		case SeverityWarn:
			s.Warn++
		case SeverityInfo:
			s.Info++
		case SeverityOK:
			s.OK++
		}
	}
	return s
}
