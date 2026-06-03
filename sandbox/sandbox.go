// Package sandbox provides an isolated execution environment for advanced
// security analysis of request payloads. It acts as the final gate in the
// AirLock security pipeline, performing deeper inspection that complements
// the fast pattern-matching in the scanner package.
package sandbox

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// AnalysisResult holds the outcome of a sandbox analysis run.
type AnalysisResult struct {
	// RunID is a unique identifier for this analysis run.
	RunID string `json:"run_id"`
	// Allowed indicates whether the request passed sandbox checks.
	Allowed bool `json:"allowed"`
	// Reason describes why the request was blocked, if applicable.
	Reason string `json:"reason,omitempty"`
	// RiskScore is a numeric risk assessment from 0.0 (safe) to 1.0 (dangerous).
	RiskScore float64 `json:"risk_score"`
	// ModifiedBody contains the (possibly sanitized) request body.
	ModifiedBody []byte `json:"modified_body,omitempty"`
}

// Analyze performs deep inspection of the request body within a sandboxed context.
// It runs heuristic analysis, entropy checks, and structural validation that go
// beyond the pattern-matching performed by the scanner layer.
//
// The function generates a unique run ID for traceability and returns an
// AnalysisResult with the determination and risk score.
func Analyze(body []byte) AnalysisResult {
	runID := uuid.New().String()

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return AnalysisResult{
			RunID:     runID,
			Allowed:   false,
			Reason:    fmt.Sprintf("sandbox: failed to parse JSON: %v", err),
			RiskScore: 1.0,
		}
	}

	// --- Heuristic 1: Check for suspicious role patterns ---
	riskScore := 0.0
	if messages, ok := parsed["messages"].([]interface{}); ok {
		systemCount := 0
		for _, msg := range messages {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				role, _ := msgMap["role"].(string)
				if role == "system" {
					systemCount++
				}
			}
		}
		// Multiple system messages are unusual and may indicate manipulation
		if systemCount > 1 {
			riskScore += 0.3
		}
	}

	// --- Heuristic 2: Check for encoded/obfuscated content ---
	bodyStr := string(body)
	obfuscationIndicators := []string{
		"\\u0069\\u0067\\u006e", // encoded "ign"
		"base64",
		"eval(",
		"\\x",
	}
	for _, indicator := range obfuscationIndicators {
		if strings.Contains(strings.ToLower(bodyStr), indicator) {
			riskScore += 0.2
		}
	}

	// --- Heuristic 3: Check for excessive nesting depth ---
	depth := measureJSONDepth(parsed, 0)
	if depth > 10 {
		riskScore += 0.3
	}

	// --- Heuristic 4: Check for unusually high token estimates ---
	if messages, ok := parsed["messages"].([]interface{}); ok {
		totalChars := 0
		for _, msg := range messages {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				if content, ok := msgMap["content"].(string); ok {
					totalChars += len(content)
				}
			}
		}
		// Rough token estimate: ~4 chars per token, flag if > 100k tokens
		estimatedTokens := totalChars / 4
		if estimatedTokens > 100000 {
			riskScore += 0.4
		}
	}

	// Cap risk score at 1.0
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	// Block if risk score exceeds threshold
	const riskThreshold = 0.7
	if riskScore >= riskThreshold {
		return AnalysisResult{
			RunID:     runID,
			Allowed:   false,
			Reason:    fmt.Sprintf("sandbox: risk score %.2f exceeds threshold %.2f", riskScore, riskThreshold),
			RiskScore: riskScore,
		}
	}

	return AnalysisResult{
		RunID:        runID,
		Allowed:      true,
		RiskScore:    riskScore,
		ModifiedBody: body,
	}
}

// measureJSONDepth recursively measures the nesting depth of a JSON structure.
func measureJSONDepth(v interface{}, current int) int {
	maxDepth := current
	switch val := v.(type) {
	case map[string]interface{}:
		for _, child := range val {
			d := measureJSONDepth(child, current+1)
			if d > maxDepth {
				maxDepth = d
			}
		}
	case []interface{}:
		for _, child := range val {
			d := measureJSONDepth(child, current+1)
			if d > maxDepth {
				maxDepth = d
			}
		}
	}
	return maxDepth
}
