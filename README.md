# AirLock 🔒  

**AI API Security Proxy** — A reverse proxy that sits in front of LLM APIs and inspects every request through a multi-layer security pipeline before forwarding it upstream.
  
## Architecture

```
Client → AirLock Proxy (:8080) → Security Pipeline → Upstream API
```

### Components

| Package | Description |
|---------|-------------|
| `proxy/` | Reverse proxy HTTP server using `net/http/httputil` |
| `scanner/` | Layer 1 — Fast pattern-based security scanning |
| `sandbox/` | Layer 2 — Deep heuristic analysis with risk scoring |

## Features

- 🔄 **Reverse Proxy** — Transparently forwards requests to upstream LLM APIs
- 🛡️ **Direct Injection Detection** — Catches 35+ known prompt injection patterns
- 🧪 **Indirect Injection Detection** — Detects injections hidden in RAG/tool data
- 🔒 **Context Sandboxing** — Wraps untrusted external data in security boundaries
- 📊 **Risk Scoring** — Heuristic-based risk assessment with configurable thresholds
- 📋 **Threat Event Log** — In-memory event log with stats at `/airlock/events`
- 🧬 **Obfuscation Detection** — Flags encoded/obfuscated content
- 💚 **Health Endpoint** — Built-in health check at `/airlock/health`
- 🌐 **CORS Support** — Configurable cross-origin resource sharing
- 🔔 **Webhook Alerting** — Notify Slack or any HTTP endpoint on HIGH severity blocked events

## Quick Start

### Prerequisites

- Go 1.21+

### Run

```bash
# Default upstream (https://api.openai.com)
go run ./proxy/

# Custom upstream
UPSTREAM=http://localhost:11434 go run ./proxy/
```

### Health Check

```bash
curl http://localhost:8080/airlock/health
# {"status":"ok","version":"0.1.0"}
```

### Threat Events

```bash
curl http://localhost:8080/airlock/events
# {"events":[...], "stats":{"total":5,"blocked":3,"l1_hits":2,"l2_hits":3,"high":3,"medium":2}}
```

### Test a Request

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-key" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Security Pipeline

### Layer 1 — Direct Injection Scanner (`scanner/layer1.go`)

Fast, case-insensitive substring matching against 35+ patterns:
- ✅ Instruction override attempts
- ✅ Jailbreak / DAN patterns
- ✅ System prompt extraction attempts
- ✅ Role hijacking patterns
- ✅ Token/delimiter injection
- ✅ Multilingual patterns (French, Spanish)

### Layer 2 — Context Sandbox (`sandbox/sandbox.go`)

RAG-aware indirect injection detection + data sandboxing:
- ✅ 14 RAG trigger phrase detection
- ✅ 13 indirect injection signal patterns
- ✅ Delimiter escaping (AIRLOCK tags, `</system>`, `<|im_end|>`, etc.)
- ✅ Security boundary wrapping with policy instruction
- ✅ Defense-in-depth (always sandboxes even without injection signal)

### Layer 3 — Heuristic Analysis (`sandbox/sandbox.go`)

Deep structural analysis:
- ✅ Suspicious role pattern detection
- ✅ Encoded/obfuscated content detection
- ✅ JSON nesting depth analysis
- ✅ Token count estimation
- ✅ Composite risk scoring (threshold: 0.7)

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `UPSTREAM` | `https://api.openai.com` | Upstream API URL |
| `BLOCK_INDIRECT` | `false` | Hard-block indirect injection detections |
| `WEBHOOK_URL` | _(empty — disabled)_ | URL to POST alert payloads on HIGH severity blocked events |
| `AIRLOCK_ENV` | `production` | Environment label included in webhook payloads |

## License

MIT License — see [LICENSE](LICENSE) for details.
