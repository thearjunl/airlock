package ratelimit

import (
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	// Initialize a limiter with 3 max requests per 1 second window
	limiter := &RateLimiter{
		counter: WindowCounter{
			counts: make(map[string][]time.Time),
		},
		maxRequests: 3,
		windowSize:  time.Second,
		enabled:     true,
	}

	key := "test-key"

	// 1st request should be allowed (remaining: 2)
	allowed, remaining, _ := limiter.Allow(key)
	if !allowed || remaining != 2 {
		t.Errorf("1st request: expected allowed=true, remaining=2. Got allowed=%v, remaining=%d", allowed, remaining)
	}

	// 2nd request should be allowed (remaining: 1)
	allowed, remaining, _ = limiter.Allow(key)
	if !allowed || remaining != 1 {
		t.Errorf("2nd request: expected allowed=true, remaining=1. Got allowed=%v, remaining=%d", allowed, remaining)
	}

	// 3rd request should be allowed (remaining: 0)
	allowed, remaining, _ = limiter.Allow(key)
	if !allowed || remaining != 0 {
		t.Errorf("3rd request: expected allowed=true, remaining=0. Got allowed=%v, remaining=%d", allowed, remaining)
	}

	// 4th request should be blocked (remaining: 0, resetIn > 0)
	allowed, remaining, resetIn := limiter.Allow(key)
	if allowed || remaining != 0 || resetIn <= 0 {
		t.Errorf("4th request: expected allowed=false, remaining=0, resetIn>0. Got allowed=%v, remaining=%d, resetIn=%v", allowed, remaining, resetIn)
	}

	// Sleep for 1.1s to slide past the window size
	time.Sleep(1100 * time.Millisecond)

	// Next request should be allowed again (remaining: 2)
	allowed, remaining, _ = limiter.Allow(key)
	if !allowed || remaining != 2 {
		t.Errorf("Request after sleep: expected allowed=true, remaining=2. Got allowed=%v, remaining=%d", allowed, remaining)
	}
}

func TestRateLimiter_Disabled(t *testing.T) {
	limiter := &RateLimiter{
		counter: WindowCounter{
			counts: make(map[string][]time.Time),
		},
		maxRequests: 1,
		windowSize:  time.Second,
		enabled:     false,
	}

	key := "test-key"

	// Multiple requests should be allowed since limiter is disabled
	for i := 0; i < 5; i++ {
		allowed, _, _ := limiter.Allow(key)
		if !allowed {
			t.Errorf("Request %d: expected allowed=true since rate limiter is disabled", i)
		}
	}
}

func TestRateLimiter_ExtractKey(t *testing.T) {
	limiter := &RateLimiter{}

	// Case A: Bearer token in Authorization header
	reqA := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	reqA.Header.Set("Authorization", "Bearer sk-test-token-12345")
	keyA := limiter.ExtractKey(reqA)
	h := sha256.New()
	h.Write([]byte("sk-test-token-12345"))
	expectedKeyA := fmt.Sprintf("%x", h.Sum(nil))[:16]
	if keyA != expectedKeyA {
		t.Errorf("ExtractKey Bearer token: expected %q, got %q", expectedKeyA, keyA)
	}

	// Case B: X-Forwarded-For header fallback (multiple IPs)
	reqB := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	reqB.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
	keyB := limiter.ExtractKey(reqB)
	if keyB != "203.0.113.195" {
		t.Errorf("ExtractKey X-Forwarded-For: expected '203.0.113.195', got %q", keyB)
	}

	// Case C: RemoteAddr fallback (strip port)
	reqC := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	reqC.RemoteAddr = "198.51.100.2:49152"
	keyC := limiter.ExtractKey(reqC)
	if keyC != "198.51.100.2" {
		t.Errorf("ExtractKey RemoteAddr: expected '198.51.100.2', got %q", keyC)
	}
}

func TestNewRateLimiter_EnvConfig(t *testing.T) {
	os.Setenv("RATE_LIMIT_ENABLED", "true")
	os.Setenv("RATE_LIMIT_MAX", "50")
	os.Setenv("RATE_LIMIT_WINDOW", "30s")
	defer func() {
		os.Unsetenv("RATE_LIMIT_ENABLED")
		os.Unsetenv("RATE_LIMIT_MAX")
		os.Unsetenv("RATE_LIMIT_WINDOW")
	}()

	limiter := NewRateLimiter()
	if !limiter.enabled {
		t.Error("NewRateLimiter: expected enabled=true")
	}
	if limiter.maxRequests != 50 {
		t.Errorf("NewRateLimiter: expected maxRequests=50, got %d", limiter.maxRequests)
	}
	if limiter.windowSize != 30*time.Second {
		t.Errorf("NewRateLimiter: expected windowSize=30s, got %v", limiter.windowSize)
	}
}
