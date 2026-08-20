package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cronFieldSpec defines range for a cron field.
type cronFieldSpec struct {
	name string
	min  int
	max  int
	// nameMap allows month/dow names like JAN, MON
	nameMap map[string]int
}

var monthNames = map[string]int{
	"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
	"JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}

var dowNames = map[string]int{
	"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
}

var fieldSpecs = []cronFieldSpec{
	{"minute", 0, 59, nil},
	{"hour", 0, 23, nil},
	{"day-of-month", 1, 31, nil},
	{"month", 1, 12, monthNames},
	{"day-of-week", 0, 7, dowNames},
}

// ValidateCronExpr validates a 5-field cron expression or @shortcut.
// Returns empty string on success, error description on failure.
func ValidateCronExpr(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("empty expression")
	}
	// Shortcuts: @annually, @yearly, @monthly, @weekly, @daily, @midnight, @hourly, @reboot
	switch strings.ToLower(expr) {
	case "@annually", "@yearly", "@monthly", "@weekly", "@daily", "@midnight", "@hourly", "@reboot":
		return nil
	}
	// Handle @every alias not standard but seen in some systems — reject, suggest "every" kind
	if strings.HasPrefix(expr, "@") {
		return fmt.Errorf("unknown shortcut %q", expr)
	}
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return fmt.Errorf("expected 5 fields, got %d", len(parts))
	}
	for i, p := range parts {
		if err := validateCronField(p, fieldSpecs[i]); err != nil {
			return fmt.Errorf("field %d (%s) %q: %w", i+1, fieldSpecs[i].name, p, err)
		}
	}
	return nil
}

func validateCronField(field string, spec cronFieldSpec) error {
	// Allow "?" as some Quartz uses (treat as *)
	if field == "?" {
		return nil
	}
	// Split by comma (list)
	items := strings.Split(field, ",")
	if len(items) == 0 {
		return fmt.Errorf("empty field")
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return fmt.Errorf("empty list element")
		}
		if err := validateCronFieldItem(item, spec); err != nil {
			return err
		}
	}
	return nil
}

func validateCronFieldItem(item string, spec cronFieldSpec) error {
	// Handle step: base/step
	if strings.Contains(item, "/") {
		parts := strings.SplitN(item, "/", 2)
		base := parts[0]
		stepStr := parts[1]
		if stepStr == "" {
			return fmt.Errorf("missing step value in %q", item)
		}
		step, err := strconv.Atoi(stepStr)
		if err != nil || step <= 0 {
			return fmt.Errorf("invalid step %q in %q", stepStr, item)
		}
		if base == "*" || base == "" {
			return nil
		}
		// base is range or single value
		return validateCronRange(base, spec)
	}
	return validateCronRange(item, spec)
}

func validateCronRange(s string, spec cronFieldSpec) error {
	if s == "*" {
		return nil
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		loStr := strings.TrimSpace(parts[0])
		hiStr := strings.TrimSpace(parts[1])
		lo, err := parseCronValue(loStr, spec)
		if err != nil {
			return err
		}
		hi, err := parseCronValue(hiStr, spec)
		if err != nil {
			return err
		}
		// Normalize dow 7 -> 0 for comparison
		if spec.name == "day-of-week" {
			if lo == 7 {
				lo = 0
			}
			if hi == 7 {
				hi = 0
			}
		}
		if lo > hi {
			return fmt.Errorf("range start %d > end %d", lo, hi)
		}
		return nil
	}
	// Single value
	_, err := parseCronValue(s, spec)
	return err
}

func parseCronValue(s string, spec cronFieldSpec) (int, error) {
	sUp := strings.ToUpper(s)
	if spec.nameMap != nil {
		if v, ok := spec.nameMap[sUp]; ok {
			return v, nil
		}
		// Allow numeric still
	}
	// Also handle "*" already filtered, but "*/" case handled earlier
	if s == "*" {
		return spec.min, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q for %s", s, spec.name)
	}
	// dow 7 is alias for 0 (Sunday)
	if spec.name == "day-of-week" && v == 7 {
		return 7, nil
	}
	if v < spec.min || v > spec.max {
		return 0, fmt.Errorf("value %d out of range [%d-%d] for %s", v, spec.min, spec.max, spec.name)
	}
	return v, nil
}

// ValidateSchedule validates the schedule object from OpenClaw cron jobs.
func ValidateSchedule(sched map[string]any) error {
	if sched == nil {
		return fmt.Errorf("missing schedule")
	}
	kind, _ := sched["kind"].(string)
	switch kind {
	case "cron":
		expr, _ := sched["expr"].(string)
		if expr == "" {
			return fmt.Errorf("cron schedule missing expr")
		}
		if err := ValidateCronExpr(expr); err != nil {
			return fmt.Errorf("invalid cron expr %q: %w", expr, err)
		}
		// tz optional, validate if present
		if tz, ok := sched["tz"].(string); ok && tz != "" {
			if _, err := time.LoadLocation(tz); err != nil {
				return fmt.Errorf("invalid timezone %q: %w", tz, err)
			}
		}
		return nil
	case "every":
		ms, ok := sched["everyMs"]
		if !ok {
			return fmt.Errorf("every schedule missing everyMs")
		}
		var msVal float64
		switch v := ms.(type) {
		case float64:
			msVal = v
		case int:
			msVal = float64(v)
		case int64:
			msVal = float64(v)
		default:
			return fmt.Errorf("everyMs wrong type %T", ms)
		}
		if msVal <= 0 {
			return fmt.Errorf("everyMs must be > 0, got %v", msVal)
		}
		if msVal < 60000 {
			return fmt.Errorf("everyMs %v is < 1 minute — suspicious", msVal)
		}
		return nil
	case "at":
		atStr, _ := sched["at"].(string)
		if atStr == "" {
			return fmt.Errorf("at schedule missing at timestamp")
		}
		if _, err := time.Parse(time.RFC3339, atStr); err != nil {
			// also try without timezone
			if _, err2 := time.Parse("2006-01-02T15:04:05", atStr); err2 != nil {
				return fmt.Errorf("invalid at timestamp %q: %w", atStr, err)
			}
		}
		return nil
	case "":
		return fmt.Errorf("schedule missing kind")
	default:
		return fmt.Errorf("unknown schedule kind %q", kind)
	}
}
