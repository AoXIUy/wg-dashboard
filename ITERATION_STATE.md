# WireGuard Pro Dashboard - Autonomous Iteration State Machine

## Current Status Overview
- **Active Phase**: Phase 2+ Continuous Autonomous Evolution
- **Completed Iterations**: 10
- **Platform**: Windows / Linux (Cross-platform pure Go `CGO_ENABLED=0`)
- **Single-Binary Build**: Verified (0 CGO, 0 external MySQL, 0 external Redis, 0 required local MMDB files)
- **Host Isolation Policy**: `./.sandbox_data/` strictly enforced; NO host network changes; MockExecutor ready for automated validation.
- **Test Suite Status**: 100% PASS (Unit tests, E2E Mock HTTP API & SSE tests, Benchmarks)

---

## Roadmap & Backlog

### Phase 1: Single-Binary Lightweight Architecture (Core Objective - COMPLETE ✅)
- [x] **Iteration 1: Host Isolation & Mock Layer (MockExecutor)**
  - [x] Abstract `WireGuardExecutor` interface supporting device state, config CRUD, syncconf, ping, and traceroute.
  - [x] Implement `MockExecutor` with realistic dynamic peer simulation, traffic growth, handshake timing, and RTT.
  - [x] Implement safe path resolution for configs (sandboxed in `./.sandbox_data/configs/`).
  - [x] Wire `-mock` flag and `WG_MOCK=true` environment variable.
  - [x] Add unit tests for `MockExecutor` (`executor_mock_test.go`).
- [x] **Iteration 2: In-Process Memory Engine (Eliminate Redis)**
  - [x] Implement concurrent thread-safe `EventBus` with channel fanout for SSE real-time traffic broadcasts (`eventbus.go`).
  - [x] Implement concurrent `MemoryCache` with TTL, LRU eviction, and Hash operations for peer state and analysis reports (`cache_mem.go`).
  - [x] Decouple `collector.go`, `precompute.go`, `sse.go`, and `server.go` from `github.com/go-redis/redis/v8`.
  - [x] Remove Redis connection retry, metrics, and flags.
  - [x] Add unit tests and race condition checks (`cache_mem_test.go`).
- [x] **Iteration 3: Pure Go Embedded Storage (Eliminate MySQL)**
  - [x] Add `modernc.org/sqlite` (pure Go SQLite driver, zero CGO).
  - [x] Refactor schema creation for SQLite (`traffic_history`, `peer_aliases`, `peer_configs`, `traffic_hourly`).
  - [x] Translate MySQL-specific syntax (`ON DUPLICATE KEY UPDATE` -> `INSERT ... ON CONFLICT DO UPDATE`, SQLite `strftime` date functions).
  - [x] Implement SQLite-safe transaction batch writes in `TrafficBuffer.Flush()`.
  - [x] Implement auto-downsampling, aggregation, and expiration cleaner (`-days`).
  - [x] Store database exclusively in `./.sandbox_data/wg_dashboard.db`.
  - [x] Update backup directory to `./.sandbox_data/backups/`.
- [x] **Iteration 4: GeoIP Graceful Degradation & Full Asset Embedding**
  - [x] Update `pkg/ipapi` to gracefully degrade to memory cache + public API when `.mmdb` files are missing.
  - [x] Embed both `index.html` and `static/` directory into single binary using `//go:embed`.
  - [x] Serve static files via `http.FS(embeddedFS)`.
  - [x] Add embedded asset unit tests (`server_embed_test.go`).
- [x] **Iteration 5: Phase 1 Verification & End-to-End Test Suite**
  - [x] Ensure `CGO_ENABLED=0 go build ./...` succeeds cleanly.
  - [x] Full test coverage suite (`go test -v ./...`).
  - [x] Mock daemon startup test on dynamic free port (`127.0.0.1:0`), verify 12 distinct endpoints (`e2e_mock_test.go`).

---

### Phase 2+: Continuous Autonomous Evolution (IN PROGRESS 🚀)
- [x] **Iteration 6: Deployment & Documentation Modernization**
  - [x] Rewrite `Dockerfile` to multi-stage scratch/Alpine single-binary container.
  - [x] Simplify `docker-compose.yml` to a standalone single container with `./data` volume.
  - [x] Update `README.md` to reflect zero external dependencies, mock mode, and embedded assets.
- [x] **Iteration 7: Benchmark Suite & Memory Concurrency Race Prevention**
  - [x] Add `benchmark_test.go` benchmarking EventBus (2.4M ops/sec), MemoryCache (1.3M ops/sec), HealthScore (44M ops/sec), and SQLite batch inserts (10,000+ rows/sec).
  - [x] Fix copy-on-write map concurrency race in `MemoryCache.HSet/HGet`.
- [x] **Iteration 8: Security & Observability Hardening**
  - [x] Enhance Prometheus `/api/metrics` with runtime goroutines, memory allocation, sys memory, GC count, and EventBus subscriber gauge.
  - [x] Add stale IP record background cleaner (`StartStaleCleaner`) in `ratelimit.go`.
  - [x] Add peer name CRLF injection validation and length bounds in `api_manage.go`.
- [x] **Iteration 9: Frontend UX & SSE Resiliency**
  - [x] Add exponential backoff reconnection (1s -> 15s) with live indicator pill in header.
  - [x] Fix Chart.js theme updating null-pointer exception on charts without scale objects (pie charts).
  - [x] Ensure component unmount timer and event source cleanup.
- [x] **Iteration 10: SQLite Storage Maintenance & Graceful Shutdown**
  - [x] Enable `auto_vacuum(INCREMENTAL)` pragma in SQLite DSN.
  - [x] Add `PRAGMA incremental_vacuum` and `PRAGMA optimize` to periodic maintenance cycle.
  - [x] Checkpoint SQLite WAL (`PRAGMA wal_checkpoint(TRUNCATE)`) and close database cleanly on graceful shutdown.

### Backlog for Subsequent Iterations
- [ ] **Iteration 11**: Automated Config Backup & Export/Import API (allow downloading and restoring encrypted or plain JSON peer configs via REST).
- [ ] **Iteration 12**: Advanced Peer Diagnostics & Health Metrics (jitter estimation, packet loss simulation in MockExecutor, packet loss display in UI).
- [ ] **Iteration 13**: High-Density Traffic Downsampling Visualization (adaptive chart downsampling for long-range 7d/30d queries to keep browser smooth).

---

## Iteration Log
- **Iter 0 (Inspection)**: Codebase scanned. Found dependencies on MySQL, Redis, MaxMind mmdb, wg/wg-quick/wgctrl, external ping/traceroute commands. Established baseline build and safety constraints.
- **Iter 1 (Mock Layer)**: Implemented `WireGuardExecutor` interface, `MockExecutor`, and `RealExecutor`. Rewrote all system command calls to use the executor.
- **Iter 2 (Redis Removal)**: Created `EventBus` and `MemoryCache`. Completely eliminated `go-redis/redis/v8`.
- **Iter 3 (MySQL Removal)**: Replaced MySQL with pure Go SQLite (`modernc.org/sqlite`, WAL mode). Added downsampled archiving table and automatic retention pruner.
- **Iter 4 (Embed & GeoIP)**: Embedded `index.html` and `static/` with `//go:embed`. Implemented GeoIP auto-degradation to public API + memory cache.
- **Iter 5 (E2E Integration Test)**: Comprehensive mock E2E test covering 12 endpoints. Single-binary build verified (`CGO_ENABLED=0`).
- **Iter 6 (Docs & Container)**: Single-binary Dockerfile and standalone docker-compose.yml. README.md updated.
- **Iter 7 (Benchmarks & Concurrency Fix)**: Benchmarking suite added. Fixed concurrency race in `MemoryCache.HSet/HGet`.
- **Iter 8 (Security & Observability)**: Process metrics, login rate limiter cleaner, config injection sanitization.
- **Iter 9 (Frontend SSE & UX)**: Exponential backoff SSE reconnection, UI pill status indicator, Chart.js pie chart theme fix.
- **Iter 10 (SQLite Maintenance & Shutdown)**: Auto-vacuum pragma, query planner optimization, and WAL checkpoint on graceful shutdown.
