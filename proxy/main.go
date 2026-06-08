// Package main implements the AirLock reverse proxy server.
// AirLock sits in front of LLM APIs (e.g., OpenAI) and inspects every
// request through a multi-layer security pipeline before forwarding
// it to the upstream service.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/thearjunl/airlock/alerting"
	"github.com/thearjunl/airlock/config"
	"github.com/thearjunl/airlock/sandbox"
	"github.com/thearjunl/airlock/scanner"
)

const (
	// Version is the current AirLock version.
	Version = "0.1.0"
	// DefaultUpstream is the default upstream API URL.
	DefaultUpstream = "https://api.openai.com"
	// ListenAddr is the address the proxy listens on.
	ListenAddr = ":8080"
)

func main() {
	upstream := os.Getenv("UPSTREAM")
	if upstream == "" {
		upstream = DefaultUpstream
	}

	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("Failed to parse upstream URL %q: %v", upstream, err)
	}

	log.Printf("🔒 AirLock v%s starting", Version)
	log.Printf("   Upstream: %s", upstreamURL.String())
	log.Printf("   Listening on %s", ListenAddr)

	// Load custom rules from YAML (non-fatal if missing)
	loadCustomRules()

	// Initialise webhook alerting
	wc := alerting.NewWebhookClient()
	SetWebhookClient(wc)
	if wc.Enabled() {
		log.Printf("   🔔 Webhook alerting: enabled")
	} else {
		log.Printf("   🔔 Webhook alerting: disabled (set WEBHOOK_URL to enable)")
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		writeJSONError(w, http.StatusBadGateway, "upstream unavailable")
	}

	// Set up router
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/airlock/health", healthHandler).Methods("GET")

	// Threat event log endpoint
	router.HandleFunc("/airlock/events", eventsHandler).Methods("GET")

	// Intercepted endpoint: POST /v1/chat/completions
	router.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		handleChatCompletions(w, r, proxy, upstreamURL)
	}).Methods("POST")

	// Serve the dashboard static files at /dashboard/
	dashboardDir := findDashboardDir()
	if dashboardDir != "" {
		log.Printf("   Dashboard: serving from %s", dashboardDir)
		fs := http.FileServer(http.Dir(dashboardDir))
		router.PathPrefix("/dashboard/").Handler(
			http.StripPrefix("/dashboard/", fs),
		)
	}

	// All other requests pass through to the upstream proxy
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = upstreamURL.Host
		proxy.ServeHTTP(w, r)
	})

	// Configure CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	handler := c.Handler(router)

	// Start server
	server := &http.Server{
		Addr:         ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

// healthHandler returns the health status and version of the AirLock proxy.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": Version,
	})
}

// eventsHandler returns all recorded threat events and aggregate statistics.
func eventsHandler(w http.ResponseWriter, r *http.Request) {
	events, stats := getEventsAndStats()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"stats":  stats,
	})
}

// handleChatCompletions intercepts POST /v1/chat/completions, runs the
// security pipeline on the request body, and either blocks or forwards.
func handleChatCompletions(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, upstreamURL *url.URL) {
	startTime := time.Now()

	// Read the full request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	log.Printf("Intercepted POST /v1/chat/completions (%d bytes)", len(body))

	// Run the security pipeline
	modifiedBody, allowed, reason := processSecurityPipeline(body)

	if !allowed {
		log.Printf("🚫 Request BLOCKED (%s) [%v]", reason, time.Since(startTime))
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("AirLock blocked: %s", reason))
		return
	}

	log.Printf("✅ Request ALLOWED [%v]", time.Since(startTime))

	// Replace the request body with the (possibly modified) body
	r.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	r.ContentLength = int64(len(modifiedBody))
	r.Host = upstreamURL.Host

	// Forward to upstream
	proxy.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// Security Pipeline
// ---------------------------------------------------------------------------

// processSecurityPipeline runs the request body through all security layers.
// Returns the (possibly modified) body, whether the request is allowed,
// and a reason string if it was blocked.
func processSecurityPipeline(body []byte) ([]byte, bool, string) {
	model := extractModel(body)

	// Layer 1: Direct prompt injection detection
	if matched, matchInfo := scanner.Layer1ScanDetailed(body); matched {
		log.Printf("🔍 Layer1 matched pattern: %q (Rule: %s, Action: %s, Severity: %s)", matchInfo.Pattern, matchInfo.RuleID, matchInfo.Action, matchInfo.Severity)
		blocked := matchInfo.Action == "block"
		recordEvent("L1_STREAM", "DIRECT_INJECTION", matchInfo.Severity, matchInfo.Pattern, model, blocked)
		if blocked {
			return nil, false, fmt.Sprintf("Direct injection: %s", matchInfo.Pattern)
		}
	}

	// Layer 2: ContextSandbox — indirect injection detection + wrapping
	sandboxedBody, injectionDetected, snippet := sandbox.SandboxTransform(body)
	if injectionDetected {
		blockIndirect := os.Getenv("BLOCK_INDIRECT")
		if strings.EqualFold(blockIndirect, "true") {
			log.Printf("🚫 Indirect injection BLOCKED — snippet: %.200s", snippet)
			recordEvent("L2_SANDBOX", "INDIRECT_INJECTION", "HIGH", snippet, model, true)
			return nil, false, fmt.Sprintf("Indirect injection detected in external data: %s", snippet)
		}
		// Log as MEDIUM severity but allow the sandboxed body through
		log.Printf("⚠️  [MEDIUM] Indirect injection detected but forwarding sandboxed body — snippet: %.200s", snippet)
		recordEvent("L2_SANDBOX", "INDIRECT_INJECTION", "MEDIUM", snippet, model, false)
	}

	// Layer 3: Deep heuristic analysis on the (possibly sandboxed) body
	analysisResult := sandbox.Analyze(sandboxedBody)
	if !analysisResult.Allowed {
		return nil, false, analysisResult.Reason
	}

	return analysisResult.ModifiedBody, true, ""
}

// writeJSONError writes a structured JSON error response.
// findDashboardDir locates the dashboard directory relative to the working
// directory or the executable path. Returns "" if not found.
func findDashboardDir() string {
	candidates := []string{
		"dashboard",
		"../dashboard",
	}

	// Also try relative to the executable
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "dashboard"),
			filepath.Join(exeDir, "..", "dashboard"),
		)
	}

	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			if abs, err := filepath.Abs(dir); err == nil {
				return abs
			}
			return dir
		}
	}
	log.Println("⚠️  Dashboard directory not found — /dashboard/ route disabled")
	return ""
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    "airlock_error",
		},
	})
}

// ---------------------------------------------------------------------------
// Custom Rules Loader
// ---------------------------------------------------------------------------

// loadCustomRules attempts to load config/rules.yaml from several candidate
// locations relative to the working directory and the executable. If the file
// is not found, a warning is logged and AirLock continues with built-in
// defaults only.
func loadCustomRules() {
	candidates := []string{
		"config/rules.yaml",
		"../config/rules.yaml",
	}

	// Also try relative to the executable
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "config", "rules.yaml"),
			filepath.Join(exeDir, "..", "config", "rules.yaml"),
		)
	}

	var cfg *config.RulesConfig
	var loadErr error

	for _, path := range candidates {
		cfg, loadErr = config.LoadRules(path)
		if loadErr == nil {
			break
		}
	}

	if cfg == nil {
		log.Printf("⚠️  No custom rules file found — continuing with built-in defaults")
		return
	}

	var l1Count, l2Count int

	for _, rule := range cfg.Rules {
		switch strings.ToUpper(rule.Layer) {
		case "L1":
			if strings.ToLower(rule.Type) == "keyword" && len(rule.Patterns) > 0 {
				scanner.AppendCustomRule(rule.ID, rule.Name, rule.Patterns, rule.Action, rule.Severity)
				l1Count += len(rule.Patterns)
				log.Printf("   📏 Rule %s (%s): added %d L1 keyword patterns", rule.ID, rule.Name, len(rule.Patterns))
			}
		case "L2":
			if strings.ToLower(rule.Type) == "rag_trigger" && len(rule.Patterns) > 0 {
				sandbox.AppendRAGTriggers(rule.Patterns)
				l2Count += len(rule.Patterns)
				log.Printf("   📏 Rule %s (%s): added %d L2 RAG trigger phrases", rule.ID, rule.Name, len(rule.Patterns))
			}
		default:
			log.Printf("   ⚠️  Rule %s: unknown layer %q — skipped", rule.ID, rule.Layer)
		}
	}

	total := l1Count + l2Count
	log.Printf("   Loaded %d custom rules from rules.yaml (%d L1 patterns, %d L2 triggers)", total, l1Count, l2Count)
}

