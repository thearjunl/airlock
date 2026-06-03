# AirLock Dashboard

Dark terminal-aesthetic monitoring dashboard for the AirLock security proxy.

## Quick Start

Open `index.html` directly in a browser, or serve via Docker Compose:

```bash
cd docker && docker compose up
# Dashboard: http://localhost:3000
# Proxy:     http://localhost:8080
```

## Features

- Real-time threat event log with auto-refresh (5s)
- 6 aggregate stat cards (total, blocked, L1, L2, high, medium)
- Colored badges for layer, severity, and action
- Demo data fallback when proxy is offline
- Responsive layout for desktop and mobile
- Scan-line animation and grid texture overlay

## Design Tokens

| Token | Value | Usage |
|-------|-------|-------|
| Background | `#080c10` | Page background |
| Surface | `#0d1117` | Cards, table |
| Teal | `#00d4aa` | Primary accent, L1 |
| Red | `#ff4d6d` | Blocked, HIGH |
| Orange | `#ffa500` | MEDIUM severity |
| Blue | `#58a6ff` | L2 ContextSandbox |
