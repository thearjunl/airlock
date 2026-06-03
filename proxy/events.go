// Package main — events.go
// Thread-safe in-memory threat event logging for the AirLock proxy.
// This file defines the ThreatEvent and EventStats types, the global
// event store, and helper functions for recording and retrieving events.
package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ThreatEvent represents a single security event recorded by the pipeline.
type ThreatEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Layer     string    `json:"layer"`
	Threat    string    `json:"threat"`
	Severity  string    `json:"severity"`
	Blocked   bool      `json:"blocked"`
	Snippet   string    `json:"snippet"`
	Model     string    `json:"model"`
}

// EventStats holds aggregate statistics computed from the event log.
type EventStats struct {
	Total   int `json:"total"`
	Blocked int `json:"blocked"`
	L1Hits  int `json:"l1_hits"`
	L2Hits  int `json:"l2_hits"`
	High    int `json:"high"`
	Medium  int `json:"medium"`
}

// eventStore is the global thread-safe event log.
var eventStore = struct {
	mu     sync.Mutex
	events []ThreatEvent
}{
	events: make([]ThreatEvent, 0),
}

// recordEvent appends a new ThreatEvent to the in-memory event log.
// It is safe to call from multiple goroutines concurrently.
func recordEvent(layer, threat, severity, snippet, model string, blocked bool) {
	event := ThreatEvent{
		ID:        uuid.New().String()[:8],
		Timestamp: time.Now(),
		Layer:     layer,
		Threat:    threat,
		Severity:  severity,
		Blocked:   blocked,
		Snippet:   truncateSnippet(snippet, 120),
		Model:     model,
	}

	eventStore.mu.Lock()
	eventStore.events = append(eventStore.events, event)
	eventStore.mu.Unlock()

	log.Printf("📋 Event recorded: [%s] %s/%s blocked=%v model=%q snippet=%.60s",
		event.ID, layer, threat, blocked, model, snippet)
}

// getEventsAndStats returns a snapshot of all events and computed statistics.
func getEventsAndStats() ([]ThreatEvent, EventStats) {
	eventStore.mu.Lock()
	defer eventStore.mu.Unlock()

	// Copy the slice so the caller doesn't hold the lock
	snapshot := make([]ThreatEvent, len(eventStore.events))
	copy(snapshot, eventStore.events)

	var stats EventStats
	stats.Total = len(snapshot)
	for _, e := range snapshot {
		if e.Blocked {
			stats.Blocked++
		}
		switch e.Layer {
		case "L1_STREAM":
			stats.L1Hits++
		case "L2_SANDBOX":
			stats.L2Hits++
		}
		switch e.Severity {
		case "HIGH":
			stats.High++
		case "MEDIUM":
			stats.Medium++
		}
	}

	return snapshot, stats
}

// truncateSnippet returns the first n characters of s, or s itself if shorter.
func truncateSnippet(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// extractModel attempts to extract the "model" field from a JSON request body.
func extractModel(body []byte) string {
	var partial struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &partial); err == nil && partial.Model != "" {
		return partial.Model
	}
	return "unknown"
}
