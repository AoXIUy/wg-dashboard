# WireGuard Pro Dashboard - Autonomous Iteration State Machine

## Current Status Overview
- **Active Phase**: Phase 1 - Elimination of External Dependencies & Mock Host Isolation
- **Current Iteration**: Iteration 1
- **Platform**: Windows / Linux (Cross-platform pure Go `CGO_ENABLED=0`)
- **Isolation Policy**: `./.sandbox_data/` strictly enforced; NO host network changes; MockExecutor ready for automated validation.

---

## Roadmap & Backlog

### Phase 1: Single-Binary Lightweight Architecture (Core Objective)
- [ ] **Iteration 1: Host Isolation & Mock Layer (MockExecutor)**
  - [x] Analyze codebase dependencies and execution paths (`wg`, `wg-quick`, `/etc/wireguard`, ping, traceroute).
  - [ ] Abstract `WireGuardExecutor` interface supporting device state, config CRUD, syncconf, ping, and traceroute.
  - [ ] Implement `MockExecutor` with realistic dynamic peer simulation, traffic growth, handshake timing, and RTT.
  - [ ] Implement safe path resolution for configs (sandboxed in `./.sandbox_data/configs/` when mock/sandboxed).
  - [ ] Wire `-mock` flag and `WG_MOCK=true` environment variable.
  - [ ] Add unit tests for `MockExecutor` (`go test -v -race`).
- [ ] **Iteration 2: In-Process Memory Engine (Eliminate Redis)**
  - [ ] Implement concurrent thread-safe `MemoryEventBus` with channel fanout for SSE real-time traffic broadcasts.
  - [ ] Implement concurrent `MemoryCache` with TTL, LRU eviction, and Hash operations for peer state and analysis reports.
  - [ ] Decouple `collector.go`, `precompute.go`, `sse.go`, and `server.go` from `github.com/go-redis/redis/v8`.
  - [ ] Eliminate Redis connection retry, metrics, and flags.
  - [ ] Add unit tests and race condition checks for EventBus and MemoryCache.
- [ ] **Iteration 3: Pure Go Embedded Storage (Eliminate MySQL)**
  - [ ] Add `modernc.org/sqlite` (pure Go SQLite driver, zero CGO).
  - [ ] Refactor schema creation for SQLite (`traffic_history`, `peer_aliases`, `peer_configs`).
  - [ ] Translate MySQL-specific syntax (`ON DUPLICATE KEY UPDATE` -> `INSERT ... ON CONFLICT DO UPDATE`, `UNIX_TIMESTAMP`, etc.).
  - [ ] Implement SQLite-safe transaction batch writes in `TrafficBuffer.Flush()`.
  - [ ] Implement auto-downsampling, aggregation, and expiration cleaner (`-days`).
  - [ ] Store database exclusively in `./.sandbox_data/wg_dashboard.db`.
  - [ ] Update backup directory to `./.sandbox_data/backups/`.
- [ ] **Iteration 4: GeoIP Graceful Degradation & Full Asset Embedding**
  - [ ] Update `pkg/ipapi` to gracefully degrade to memory cache + public API when `.mmdb` files are missing.
  - [ ] Embed both `index.html` and `static/` directory into single binary using `//go:embed`.
  - [ ] Serve static files via `http.FS(embeddedFS)`.
- [ ] **Iteration 5: Phase 1 Verification & End-to-End Test Suite**
  - [ ] Ensure `CGO_ENABLED=0 go build ./...` succeeds cleanly.
  - [ ] Full test coverage suite (`go test -v -race ./...`).
  - [ ] Mock daemon startup test on dynamic free port (`127.0.0.1:0`), verify SSE & REST APIs, test graceful shutdown.

### Phase 2+: Continuous Autonomous Evolution
- [ ] **Iteration 6**: Architecture modularization (`internal/executor`, `internal/storage`, `internal/api`, etc.).
- [ ] **Iteration 7**: Benchmark suite for high-throughput traffic logging and SSE broadcasts.
- [ ] **Iteration 8**: Security enhancements (memory rate-limiter, JWT validation, config sanitization).
- [ ] **Iteration 9**: Frontend improvements (SSE automatic reconnection, dark mode enhancements).
- [ ] **Iteration 10**: Documentation & Dockerfile single-binary deployment update.

---

## Iteration Log
- **Iter 0 (Inspection)**: Codebase scanned. Found dependencies on MySQL, Redis, MaxMind mmdb, wg/wg-quick/wgctrl, external ping/traceroute commands. Established baseline build and safety constraints.
