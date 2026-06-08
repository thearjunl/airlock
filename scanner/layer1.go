// Package scanner provides security scanning layers for the AirLock proxy.
// Layer 1 implements direct prompt injection detection by performing
// case-insensitive substring matching against a comprehensive list
// of known injection patterns across the raw request body.
package scanner

import (
	"strings"
)

// injectionPatterns is the comprehensive list of direct prompt injection
// patterns to detect. Each pattern is matched case-insensitively against
// the raw JSON body string.
var injectionPatterns = []string{
	// --- Instruction override attempts ---
	"ignore previous instructions",
	"ignore all previous",
	"disregard your instructions",
	"forget your previous instructions",
	"override your instructions",

	// --- New instruction injection ---
	"your new instructions are",
	"new system prompt:",

	// --- Jailbreak / DAN attempts ---
	"do anything now",
	"you are now dan",
	"jailbreak mode",
	"developer mode enabled",

	// --- Restriction bypass ---
	"you have no restrictions",
	"pretend you have no",
	"pretend you are not",

	// --- System prompt extraction ---
	"repeat your system prompt",
	"reveal your instructions",
	"print your system message",
	"what are your exact instructions",
	"tell me your prompt",
	"output your system",

	// --- Role hijacking ---
	"you are now a",
	"from now on you are",
	"your role is now",
	"you must act as",
	"respond only as",

	// --- Token / delimiter injection ---
	"</system>",
	"<|im_end|>",
	"<|system|>",
	"[system]",

	// --- Structured injection markers ---
	"###instruction",
	"### new task",
	"[new task]",
	"[ignore above]",

	// --- Multilingual injection patterns ---
	"ignorez toutes les instructions",
	"ignorar instrucciones anteriores",
}

// CustomRule represents a custom L1 detection rule with metadata.
type CustomRule struct {
	ID       string
	Name     string
	Patterns []string
	Action   string
	Severity string
}

// MatchInfo holds metadata about a matched pattern.
type MatchInfo struct {
	Pattern  string
	Action   string
	Severity string
	RuleID   string
}

// customRules holds the registered L1 custom rules.
var customRules []CustomRule

// AppendCustomRule registers a new L1 custom rule.
func AppendCustomRule(id, name string, patterns []string, action, severity string) {
	customRules = append(customRules, CustomRule{
		ID:       id,
		Name:     name,
		Patterns: patterns,
		Action:   action,
		Severity: severity,
	})
}

// Layer1ScanDetailed scans the raw JSON body and returns match metadata.
// It checks custom rules first, then falls back to built-in patterns.
func Layer1ScanDetailed(body []byte) (bool, MatchInfo) {
	lower := strings.ToLower(string(body))

	// Scan custom rules first
	for _, rule := range customRules {
		for _, pattern := range rule.Patterns {
			if strings.Contains(lower, strings.ToLower(pattern)) {
				action := rule.Action
				if action == "" {
					action = "block"
				}
				severity := rule.Severity
				if severity == "" {
					severity = "LOW"
				}
				return true, MatchInfo{
					Pattern:  pattern,
					Action:   strings.ToLower(action),
					Severity: strings.ToUpper(severity),
					RuleID:   rule.ID,
				}
			}
		}
	}

	// Scan built-in patterns
	for _, pattern := range injectionPatterns {
		if strings.Contains(lower, pattern) {
			return true, MatchInfo{
				Pattern:  pattern,
				Action:   "block",
				Severity: "HIGH",
				RuleID:   "built-in",
			}
		}
	}

	return false, MatchInfo{}
}

// Layer1Scan scans the raw JSON body for direct prompt injection patterns
// using case-insensitive substring search.
//
// It converts the entire body to lowercase once and then checks every
// pattern in the injection list against it.
//
// Returns:
//   - (true, matchedPattern) if any injection pattern is found
//   - (false, "") if the body is clean
func Layer1Scan(body []byte) (bool, string) {
	matched, info := Layer1ScanDetailed(body)
	return matched, info.Pattern
}

// AppendPatterns adds custom patterns to the injection detection list.
// This is used by the custom rules loader to extend Layer 1 scanning
// at startup without modifying the built-in pattern table.
func AppendPatterns(patterns []string) {
	injectionPatterns = append(injectionPatterns, patterns...)
}
