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
- 🛡️ **Prompt Injection Detection** — Catches known injection patterns
- 📊 **Risk Scoring** — Heuristic-based risk assessment with configurable thresholds
- 🔍 **Payload Validation** — JSON structure, UTF-8, and size limit checks
- 🧬 **Obfuscation Detection** — Flags encoded/obfuscated content
- 💚 **Health Endpoint** — Built-in health check at `/airlock/health`
- 🌐 **CORS Support** — Configurable cross-origin resource sharing

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

### Layer 1 — Scanner (`scanner/layer1.go`)

Fast, pattern-based checks:
- ✅ JSON structure validation
- ✅ Payload size limit (1 MB)
- ✅ UTF-8 encoding validation
- ✅ Prompt injection pattern detection
- ✅ Required field validation (`model`)

### Layer 2 — Sandbox (`sandbox/sandbox.go`)

Deep heuristic analysis:
- ✅ Suspicious role pattern detection
- ✅ Encoded/obfuscated content detection
- ✅ JSON nesting depth analysis
- ✅ Token count estimation
- ✅ Composite risk scoring (threshold: 0.7)

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `UPSTREAM` | `https://api.openai.com` | Upstream API URL |

## License

MIT License — see [LICENSE](LICENSE) for details.
