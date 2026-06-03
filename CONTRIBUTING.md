# Contributing to AirLock

Thank you for your interest in contributing to AirLock! 🔒

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/airlock.git`
3. Create a feature branch: `git checkout -b feat/your-feature`
4. Make your changes
5. Run tests: `go test -v ./...`
6. Commit with conventional commit messages
7. Push and open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21+
- Make (optional, for using Makefile targets)

### Build & Run

```bash
# Build
make build

# Run locally
make run

# Run tests
make test
```

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New features
- `fix:` — Bug fixes
- `refactor:` — Code refactoring
- `docs:` — Documentation changes
- `test:` — Test additions or updates
- `chore:` — Build process or tooling changes

## Security Pipeline

When adding new security checks, consider:

1. **Layer 1 (scanner/)**: Fast, pattern-based checks. Should complete in microseconds.
2. **Layer 2 (sandbox/)**: Deeper heuristic analysis. Can take milliseconds.

New patterns should be added to the appropriate layer based on their complexity.

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to build better security tools together.
