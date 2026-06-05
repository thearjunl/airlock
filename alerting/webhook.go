// Package alerting provides webhook-based alerting for the AirLock proxy.
// When a HIGH severity threat event is recorded, an alert payload is
// dispatched asynchronously to a configured HTTP endpoint (e.g., Slack
// incoming webhook). Delivery is non-blocking and includes one automatic
// retry with 500 ms backoff on failure.
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// AlertPayload is the JSON body sent to the webhook endpoint.
// It includes a Slack-compatible "text" field so it works out of the box
// as a Slack incoming webhook.
type AlertPayload struct {
	ID           string `json:"id"`
	Timestamp    string `json:"timestamp"`
	Layer        string `json:"layer"`
	Threat       string `json:"threat"`
	Severity     string `json:"severity"`
	Blocked      bool   `json:"blocked"`
	Snippet      string `json:"snippet"`
	Model        string `json:"model"`
	ProxyVersion string `json:"proxy_version"`
	Environment  string `json:"environment"`
	Text         string `json:"text"`
}

// WebhookClient manages the connection to an external alerting endpoint.
type WebhookClient struct {
	url        string
	httpClient *http.Client
	enabled    bool
}

// NewWebhookClient creates a WebhookClient configured from environment
// variables. If WEBHOOK_URL is not set, the client is created in a
// disabled state and all Send calls become no-ops.
func NewWebhookClient() *WebhookClient {
	webhookURL := os.Getenv("WEBHOOK_URL")
	return &WebhookClient{
		url: webhookURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		enabled: webhookURL != "",
	}
}

// Enabled reports whether the webhook client is active.
func (w *WebhookClient) Enabled() bool {
	return w.enabled
}

// Send dispatches an alert for the given threat event. The call is
// non-blocking — delivery runs in a background goroutine so it never
// delays the proxy request path. On failure, a single retry is
// attempted after 500 ms.
func (w *WebhookClient) Send(id, timestamp, layer, threat, severity, snippet, model string, blocked bool) {
	if !w.enabled {
		return
	}

	env := os.Getenv("AIRLOCK_ENV")
	if env == "" {
		env = "production"
	}

	// Build Slack-compatible one-liner
	blockedStr := "detected"
	if blocked {
		blockedStr = "blocked"
	}
	text := fmt.Sprintf("🚨 [%s] %s %s by AirLock %s | Model: %s | %s",
		severity, threat, blockedStr, layer, model, snippet)

	payload := AlertPayload{
		ID:           id,
		Timestamp:    timestamp,
		Layer:        layer,
		Threat:       threat,
		Severity:     severity,
		Blocked:      blocked,
		Snippet:      snippet,
		Model:        model,
		ProxyVersion: "0.1.0",
		Environment:  env,
		Text:         text,
	}

	go w.sendWithRetry(payload)
}

// sendWithRetry attempts to POST the payload, retrying once on failure.
func (w *WebhookClient) sendWithRetry(payload AlertPayload) {
	if err := w.post(payload); err != nil {
		log.Printf("⚠️  Webhook delivery failed (attempt 1/2): %v — retrying in 500ms", err)
		time.Sleep(500 * time.Millisecond)
		if err := w.post(payload); err != nil {
			log.Printf("❌ Webhook delivery failed (attempt 2/2): %v — giving up", err)
		}
	}
}

// post marshals the payload and sends it to the webhook URL.
func (w *WebhookClient) post(payload AlertPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal alert payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AirLock/0.1.0")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", w.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: HTTP %d", w.url, resp.StatusCode)
	}

	log.Printf("✅ Webhook alert delivered: [%s] %s/%s → HTTP %d",
		payload.ID, payload.Layer, payload.Threat, resp.StatusCode)
	return nil
}
