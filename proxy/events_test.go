package main

import (
	"testing"
	"time"
)

func TestRecordEvent_AppendsToLog(t *testing.T) {
	// Clear the event store before test
	eventStore.mu.Lock()
	eventStore.events = make([]ThreatEvent, 0)
	eventStore.mu.Unlock()

	recordEvent("L1_STREAM", "DIRECT_INJECTION", "HIGH", "ignore previous instructions", "gpt-4", true)

	events, stats := getEventsAndStats()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Layer != "L1_STREAM" {
		t.Errorf("Expected layer L1_STREAM, got %q", e.Layer)
	}
	if e.Threat != "DIRECT_INJECTION" {
		t.Errorf("Expected threat DIRECT_INJECTION, got %q", e.Threat)
	}
	if e.Severity != "HIGH" {
		t.Errorf("Expected severity HIGH, got %q", e.Severity)
	}
	if !e.Blocked {
		t.Error("Expected blocked=true")
	}
	if e.Model != "gpt-4" {
		t.Errorf("Expected model gpt-4, got %q", e.Model)
	}
	if len(e.ID) != 8 {
		t.Errorf("Expected 8-char ID, got %q (%d chars)", e.ID, len(e.ID))
	}
	if stats.Total != 1 || stats.Blocked != 1 || stats.L1Hits != 1 || stats.High != 1 {
		t.Errorf("Stats mismatch: %+v", stats)
	}
}

func TestRecordEvent_SnippetTruncation(t *testing.T) {
	eventStore.mu.Lock()
	eventStore.events = make([]ThreatEvent, 0)
	eventStore.mu.Unlock()

	longSnippet := ""
	for i := 0; i < 200; i++ {
		longSnippet += "X"
	}
	recordEvent("L2_SANDBOX", "INDIRECT_INJECTION", "MEDIUM", longSnippet, "gpt-3.5-turbo", false)

	events, _ := getEventsAndStats()
	if len([]rune(events[0].Snippet)) > 120 {
		t.Errorf("Snippet should be truncated to 120 chars, got %d", len([]rune(events[0].Snippet)))
	}
}

func TestGetEventsAndStats_AggregatesCorrectly(t *testing.T) {
	eventStore.mu.Lock()
	eventStore.events = make([]ThreatEvent, 0)
	eventStore.mu.Unlock()

	recordEvent("L1_STREAM", "DIRECT_INJECTION", "HIGH", "pattern1", "gpt-4", true)
	recordEvent("L1_STREAM", "JAILBREAK", "HIGH", "pattern2", "gpt-4", true)
	recordEvent("L2_SANDBOX", "INDIRECT_INJECTION", "MEDIUM", "pattern3", "gpt-3.5-turbo", false)
	recordEvent("L2_SANDBOX", "INDIRECT_INJECTION", "HIGH", "pattern4", "claude-3", true)

	_, stats := getEventsAndStats()
	if stats.Total != 4 {
		t.Errorf("Expected total=4, got %d", stats.Total)
	}
	if stats.Blocked != 3 {
		t.Errorf("Expected blocked=3, got %d", stats.Blocked)
	}
	if stats.L1Hits != 2 {
		t.Errorf("Expected l1_hits=2, got %d", stats.L1Hits)
	}
	if stats.L2Hits != 2 {
		t.Errorf("Expected l2_hits=2, got %d", stats.L2Hits)
	}
	if stats.High != 3 {
		t.Errorf("Expected high=3, got %d", stats.High)
	}
	if stats.Medium != 1 {
		t.Errorf("Expected medium=1, got %d", stats.Medium)
	}
}

func TestGetEventsAndStats_ReturnsSnapshot(t *testing.T) {
	eventStore.mu.Lock()
	eventStore.events = make([]ThreatEvent, 0)
	eventStore.mu.Unlock()

	recordEvent("L1_STREAM", "DIRECT_INJECTION", "HIGH", "test", "gpt-4", true)

	events1, _ := getEventsAndStats()

	// Add another event after taking snapshot
	recordEvent("L2_SANDBOX", "INDIRECT_INJECTION", "MEDIUM", "test2", "gpt-4", false)

	// First snapshot should still have 1 event (it's a copy)
	if len(events1) != 1 {
		t.Errorf("Snapshot should be independent, expected 1, got %d", len(events1))
	}

	// New call should have 2
	events2, _ := getEventsAndStats()
	if len(events2) != 2 {
		t.Errorf("Expected 2 events in new snapshot, got %d", len(events2))
	}
}

func TestRecordEvent_TimestampIsRecent(t *testing.T) {
	eventStore.mu.Lock()
	eventStore.events = make([]ThreatEvent, 0)
	eventStore.mu.Unlock()

	before := time.Now()
	recordEvent("L1_STREAM", "DIRECT_INJECTION", "HIGH", "test", "gpt-4", true)
	after := time.Now()

	events, _ := getEventsAndStats()
	if events[0].Timestamp.Before(before) || events[0].Timestamp.After(after) {
		t.Error("Timestamp should be between before and after test execution")
	}
}

func TestExtractModel_ValidJSON(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	model := extractModel(body)
	if model != "gpt-4o" {
		t.Errorf("Expected gpt-4o, got %q", model)
	}
}

func TestExtractModel_InvalidJSON(t *testing.T) {
	body := []byte(`not json`)
	model := extractModel(body)
	if model != "unknown" {
		t.Errorf("Expected 'unknown', got %q", model)
	}
}

func TestExtractModel_MissingField(t *testing.T) {
	body := []byte(`{"messages":[]}`)
	model := extractModel(body)
	if model != "unknown" {
		t.Errorf("Expected 'unknown', got %q", model)
	}
}

func TestTruncateSnippet_Short(t *testing.T) {
	result := truncateSnippet("hello", 120)
	if result != "hello" {
		t.Errorf("Expected 'hello', got %q", result)
	}
}

func TestTruncateSnippet_Exact(t *testing.T) {
	s := ""
	for i := 0; i < 120; i++ {
		s += "A"
	}
	result := truncateSnippet(s, 120)
	if result != s {
		t.Error("Exact-length string should not be truncated")
	}
}

func TestTruncateSnippet_Long(t *testing.T) {
	s := ""
	for i := 0; i < 200; i++ {
		s += "B"
	}
	result := truncateSnippet(s, 120)
	if len([]rune(result)) != 120 {
		t.Errorf("Expected 120 runes, got %d", len([]rune(result)))
	}
}
