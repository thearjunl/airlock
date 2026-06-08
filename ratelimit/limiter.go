// Package ratelimit implements sliding window rate limiting for the AirLock proxy.
package ratelimit

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WindowCounter is a thread-safe sliding window counter.
type WindowCounter struct {
	mu     sync.Mutex
	counts map[string][]time.Time // key → slice of request timestamps
}

// RateLimiter holds the configuration and active window counter.
type RateLimiter struct {
	counter     WindowCounter
	maxRequests int           // maximum allowed requests in the window
	windowSize  time.Duration // sliding window duration
	enabled     bool
}

// NewRateLimiter initializes a RateLimiter from environment variables.
func NewRateLimiter() *RateLimiter {
	enabled := os.Getenv("RATE_LIMIT_ENABLED") == "true"

	maxRequests := 100
	if maxStr := os.Getenv("RATE_LIMIT_MAX"); maxStr != "" {
		if val, err := strconv.Atoi(maxStr); err == nil && val > 0 {
			maxRequests = val
		}
	}

	windowSize := time.Minute
	if winStr := os.Getenv("RATE_LIMIT_WINDOW"); winStr != "" {
		if val, err := time.ParseDuration(winStr); err == nil && val > 0 {
			windowSize = val
		}
	}

	return &RateLimiter{
		counter: WindowCounter{
			counts: make(map[string][]time.Time),
		},
		maxRequests: maxRequests,
		windowSize:  windowSize,
		enabled:     enabled,
	}
}

// Enabled reports whether the rate limiter is active.
func (r *RateLimiter) Enabled() bool {
	return r.enabled
}

// Allow checks if a request is allowed for the given key.
// It prunes timestamps older than windowSize first.
// If the limit is exceeded, it returns allowed=false, remaining=0, and the duration until reset.
// Otherwise, it records the request and returns allowed=true and the remaining count.
func (r *RateLimiter) Allow(key string) (allowed bool, remaining int, resetIn time.Duration) {
	if !r.enabled {
		return true, r.maxRequests, 0
	}

	r.counter.mu.Lock()
	defer r.counter.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.windowSize)

	timestamps := r.counter.counts[key]

	// Prune timestamps older than cutoff
	var active []time.Time
	for _, t := range timestamps {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}

	// Check if limit is hit
	if len(active) >= r.maxRequests {
		r.counter.counts[key] = active
		oldest := active[0]
		resetIn = oldest.Add(r.windowSize).Sub(now)
		if resetIn < 0 {
			resetIn = 0
		}
		return false, 0, resetIn
	}

	// Record request
	active = append(active, now)
	r.counter.counts[key] = active

	remaining = r.maxRequests - len(active)
	return true, remaining, 0
}

// ExtractKey determines the rate limit key for a given HTTP request.
// It prioritizes the Authorization header (hashing Bearer tokens),
// falls back to X-Forwarded-For, and finally falls back to req.RemoteAddr.
func (r *RateLimiter) ExtractKey(req *http.Request) string {
	// 1. Authorization header (Bearer token)
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		h := sha256.New()
		h.Write([]byte(token))
		hashStr := fmt.Sprintf("%x", h.Sum(nil))
		return hashStr[:16]
	}

	// 2. X-Forwarded-For header
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// 3. RemoteAddr (strip port)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}
