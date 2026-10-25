# WireGuard Pro Dashboard - Autonomous Iteration State Machine

## Current Status Overview
- **Active Phase**: Phase 2+ Continuous Autonomous Evolution
- **Completed Iterations**: 16
- **Platform**: Windows / Linux (Cross-platform pure Go `CGO_ENABLED=0`)
- **Single-Binary Build**: Verified (0 CGO, 0 external MySQL, 0 external Redis, 0 required local MMDB files, ~30MB single executable)
- **Host Isolation Policy**: `./.sandbox_data/` strictly enforced; NO host network changes; MockExecutor ready for automated validation.
- **Test Suite Status**: 100% PASS (15 E2E endpoints, unit tests, race-safe memory cache, and benchmarks)

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
- [x] **Iteration 11: Peer Aliases and Configs Backup Export, Import, and Storage Stats API**
  - [x] Implement `GET /api/backup/export` (downloads JSON backup of aliases & staged configs).
  - [x] Implement `POST /api/backup/import` (transactional restore with auto alias cache refresh).
  - [x] Implement `GET /api/backup/stats` (reports table row counts and sandbox directory sizes).
  - [x] Full unit test suite in `api_backup_test.go`.
- [x] **Iteration 12: Advanced Diagnostics & Network Jitter Metric**
  - [x] Add `jitter` field to `PingResponse` in `diagnostics.go`.
  - [x] Parse Linux ping `mdev` / Windows ping RTT spread.
  - [x] Add realistic jitter and 50% packet loss simulation in `MockExecutor.Ping`.
  - [x] Add 5th metric card for Network Jitter in `index.html`.
- [x] **Iteration 13: High-Density Traffic Downsampling & UNION ALL Long-Range Query Optimization**
  - [x] Add `30d` range option with adaptive 4-hour step slots.
  - [x] Optimize `getPeerHistory` and `getTrafficChartData` using `UNION ALL` across `traffic_history` and `traffic_hourly`.
  - [x] Verified seamless cross-table time series retrieval in `database_test.go`.
- [x] **Iteration 14: Version Stamping, Build Metrics, Makefile, and Cross-Platform Build Scripts**
  - [x] Add version, git commit hash, and build timestamp injection via `-ldflags`.
  - [x] Expose `wg_dashboard_build_info` gauge in Prometheus metrics and `/api/system`.
  - [x] Add `Makefile` for Linux and `build.ps1` for Windows supporting `build`, `linux-amd64`, `linux-arm64`, `test`, `bench`, and `clean`.
- [x] **Iteration 15: Frontend Interactive Backup/Restore Modal with Storage Stats**
  - [x] Add "备份" button in frontend action bar.
  - [x] Add animated modal displaying live database size, alias count, and archived row statistics.
  - [x] Support one-click JSON backup export and file-upload restore with instant notification toast.
- [x] **Iteration 16: Comprehensive E2E Regression Verification**
  - [x] Extend `e2e_mock_test.go` to 15 end-to-end endpoints.
  - [x] Verified backup stats, backup export, system build info, and network jitter under mock daemon.

### Backlog for Subsequent Iterations
- [ ] **Iteration 17**: Code Structure Modularization (gradual migration of flat packages to `internal/` packages while preserving single-binary build simplicity).
- [ ] **Iteration 18**: Config Import Diff Preview (preview diff of peers before applying an imported backup).

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
- **Iter 11 (Backup & Restore API)**: Transactional JSON export/import for aliases and configs, plus storage statistics.
- **Iter 12 (Jitter Diagnostics)**: Network jitter estimation and loss simulation for WireGuard diagnostics.
- **Iter 13 (Archive Union Optimization)**: Query downsampled hourly archives alongside live history for 7d/30d periods.
- **Iter 14 (Build Automation & Versioning)**: Version stamping, Makefile, and Windows build.ps1 for multi-arch targets.
- **Iter 15 (Backup & Restore UI)**: Frontend modal with live database metrics, one-click export, and file upload import.
- **Iter 16 (E2E Regression)**: Expanded test suite to 15 end-to-end endpoints verifying all new capabilities under sandbox isolation.
