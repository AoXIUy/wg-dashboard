package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// ================= 数据库初始化 =================

// initDB 连接 SQLite，配置 WAL 模式和性能参数，创建所有必要的表
func initDB() error {
	var err error

	// 确保数据库目录存在
	dbDir := filepath.Dir(DBPath)
	if dbDir != "" && dbDir != "." {
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return fmt.Errorf("创建数据库目录失败: %w", err)
		}
	}

	db, err = sql.Open("sqlite", DBPath)
	if err != nil {
		return fmt.Errorf("打开数据库连接失败: %w", err)
	}

	// SQLite 单连接模式：WAL 下读写可并发，但写入仍需串行
	// 设置较小的连接池避免 "database is locked" 错误
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // 不限制连接寿命

	// 健康检查
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("数据库连接测试失败: %w", err)
	}

	// SQLite 性能优化 PRAGMA（针对 RK3399 eMMC 调优）
	pragmas := []string{
		"PRAGMA journal_mode=WAL",            // WAL 模式：读写并发，写入合并
		"PRAGMA synchronous=NORMAL",          // 平衡安全与性能（WAL 模式下 NORMAL 已足够安全）
		"PRAGMA cache_size=-8000",            // 8MB 页缓存（负值表示 KB）
		"PRAGMA busy_timeout=5000",           // 忙等待 5 秒
		"PRAGMA wal_autocheckpoint=1000",     // 每 1000 页自动 checkpoint
		"PRAGMA temp_store=MEMORY",           // 临时表使用内存
		"PRAGMA mmap_size=67108864",          // 64MB mmap 映射，减少 read 系统调用
		"PRAGMA page_size=4096",              // 4KB 页大小（匹配 eMMC 块大小）
		"PRAGMA locking_mode=EXCLUSIVE",      // 单进程模式，减少锁检查开销
		"PRAGMA journal_size_limit=67108864", // 限制 WAL 文件最大 64MB，防止暴增
	}

	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			logger.Printf("PRAGMA 设置失败 (%s): %v", pragma, err)
		}
	}

	// 创建表 1: traffic_history（原始流量记录）
	schema1 := `
	CREATE TABLE IF NOT EXISTS traffic_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		peer_public_key TEXT NOT NULL,
		endpoint TEXT DEFAULT '',
		rx_bytes INTEGER NOT NULL,
		tx_bytes INTEGER NOT NULL,
		rx_rate REAL DEFAULT 0,
		tx_rate REAL DEFAULT 0,
		is_online INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_peer_time ON traffic_history (peer_public_key, timestamp);
	CREATE INDEX IF NOT EXISTS idx_time ON traffic_history (timestamp);`

	if _, err = db.ExecContext(ctx, schema1); err != nil {
		return fmt.Errorf("创建 traffic_history 表失败: %w", err)
	}

	// 创建表 2: peer_aliases
	schema2 := `
	CREATE TABLE IF NOT EXISTS peer_aliases (
		public_key TEXT PRIMARY KEY,
		alias TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1
	);`

	if _, err = db.ExecContext(ctx, schema2); err != nil {
		return fmt.Errorf("创建 peer_aliases 表失败: %w", err)
	}

	// 迁移: 为 peer_aliases 添加 enabled 字段（若不存在）
	// SQLite 不支持 ADD COLUMN IF NOT EXISTS，需查询 table_info
	var colCount int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('peer_aliases') WHERE name='enabled'`).Scan(&colCount)
	if err == nil && colCount == 0 {
		_, _ = db.ExecContext(ctx, `ALTER TABLE peer_aliases ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1`)
	}

	// 创建表 3: peer_configs（存储禁用 peer 的完整配置块，用于内核层禁用/启用）
	schema3 := `
	CREATE TABLE IF NOT EXISTS peer_configs (
		public_key TEXT PRIMARY KEY,
		conf_name  TEXT NOT NULL,
		peer_block TEXT NOT NULL,
		saved_at   INTEGER NOT NULL
	);`

	if _, err = db.ExecContext(ctx, schema3); err != nil {
		return fmt.Errorf("创建 peer_configs 表失败: %w", err)
	}

	// 创建表 4: traffic_hourly（降采样聚合表，RK3399 存储优化核心）
	schema4 := `
	CREATE TABLE IF NOT EXISTS traffic_hourly (
		hour_ts      INTEGER NOT NULL,
		peer_key     TEXT NOT NULL,
		avg_rx_rate  REAL DEFAULT 0,
		avg_tx_rate  REAL DEFAULT 0,
		max_rx_rate  REAL DEFAULT 0,
		max_tx_rate  REAL DEFAULT 0,
		total_rx     INTEGER DEFAULT 0,
		total_tx     INTEGER DEFAULT 0,
		online_pct   REAL DEFAULT 0,
		sample_count INTEGER DEFAULT 0,
		PRIMARY KEY (hour_ts, peer_key)
	);
	CREATE INDEX IF NOT EXISTS idx_hourly_peer ON traffic_hourly (peer_key, hour_ts);`

	if _, err = db.ExecContext(ctx, schema4); err != nil {
		return fmt.Errorf("创建 traffic_hourly 表失败: %w", err)
	}

	logger.Println("SQLite 数据库初始化成功 (WAL 模式)")

	// 初始化分析引擎
	analysisEngine = NewAnalysisEngine(db)

	return nil
}

// closeDB 关闭数据库连接和 GeoIP 提供器
func closeDB() {
	if db != nil {
		// 关闭前执行最后一次 WAL checkpoint
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		if err := db.Close(); err != nil {
			logger.Printf("数据库关闭失败: %v", err)
		}
	}
	if ipProvider != nil {
		if err := ipProvider.Close(); err != nil {
			logger.Printf("GeoIP 关闭失败: %v", err)
		}
	}
}

// ================= 数据清理 =================

// startCleaner 启动定时清理任务，每 24 小时删除超过 Retention 天的历史数据
func startCleaner(ctx context.Context) {
	if Retention <= 0 {
		logger.Println("数据清理器已禁用 (保留天数 <= 0)")
		return
	}

	logger.Printf("数据清理器已启动 (保留 %d 天)", Retention)
	defer logger.Println("数据清理器已停止")

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// 启动时立即执行一次
	cleanOldData(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanOldData(ctx)
		}
	}
}

// cleanOldData 删除超出保留期的历史流量记录（原始表 + 聚合表）
func cleanOldData(ctx context.Context) {
	expireTime := time.Now().AddDate(0, 0, -Retention).Unix()

	cleanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 清理原始表
	result, err := db.ExecContext(cleanCtx, `DELETE FROM traffic_history WHERE timestamp < ?`, expireTime)
	if err != nil {
		logger.Printf("清理旧数据失败: %v", err)
	} else if rows, err := result.RowsAffected(); err == nil && rows > 0 {
		logger.Printf("已清理 %d 条原始历史记录", rows)
	}

	// 清理聚合表
	result2, err2 := db.ExecContext(cleanCtx, `DELETE FROM traffic_hourly WHERE hour_ts < ?`, expireTime)
	if err2 != nil {
		logger.Printf("清理旧聚合数据失败: %v", err2)
	} else if rows, err := result2.RowsAffected(); err == nil && rows > 0 {
		logger.Printf("已清理 %d 条聚合历史记录", rows)
	}
}

// ================= 异步写入 =================

// startAsyncWriter 定时将内存缓冲中的流量日志批量写入 SQLite
func startAsyncWriter(ctx context.Context) {
	logger.Println("异步写入器已启动")
	defer logger.Println("异步写入器已停止")

	ticker := time.NewTicker(WriteInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 关闭前最后一次刷新
			if batch := trafficBuffer.Flush(); batch != nil {
				flushSQLite(batch)
			}
			return
		case <-ticker.C:
			if batch := trafficBuffer.Flush(); batch != nil {
				flushSQLite(batch)
			}
		}
	}
}

// flushSQLite 将一批日志写入 SQLite，失败时重试并回退到文件
func flushSQLite(batch []ProcessedLog) {
	if len(batch) == 0 {
		return
	}

	for attempt := 0; attempt < MaxRetries; attempt++ {
		err := attemptFlushSQLite(batch)
		if err == nil {
			return
		}

		logger.Printf("SQLite 写入失败 (尝试 %d/%d): %v", attempt+1, MaxRetries, err)
		metrics.IncFailedWrites()

		if attempt < MaxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	// 最终失败，备份到本地文件
	backupToFile(batch)
}

// attemptFlushSQLite 使用事务批量插入（SQLite 单事务内多条 INSERT 仅需 1 次 fsync）
func attemptFlushSQLite(batch []ProcessedLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO traffic_history 
		(timestamp, peer_public_key, endpoint, rx_bytes, tx_bytes, rx_rate, tx_rate, is_online) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("准备语句失败: %w", err)
	}
	defer stmt.Close()

	// 收集失败条目，事务提交后备份，避免静默丢失
	var failedEntries []ProcessedLog
	for _, logEntry := range batch {
		if _, err := stmt.ExecContext(ctx,
			logEntry.Timestamp,
			logEntry.PublicKey,
			logEntry.Endpoint,
			logEntry.RxBytes,
			logEntry.TxBytes,
			logEntry.RxRate,
			logEntry.TxRate,
			boolToInt(logEntry.IsOnline),
		); err != nil {
			failedEntries = append(failedEntries, logEntry)
			logger.Printf("插入记录失败 [%s]: %v", logEntry.PublicKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	// 将本次失败的条目备份到文件，确保数据不丢失
	if len(failedEntries) > 0 {
		logger.Printf("批量插入完成，成功 %d/%d 条，失败 %d 条已备份",
			len(batch)-len(failedEntries), len(batch), len(failedEntries))
		backupToFile(failedEntries)
	}

	return nil
}

// boolToInt 将 bool 转为 SQLite 兼容的 0/1 整数
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// backupToFile 将写库失败的记录以 JSON 格式备份到本地文件
func backupToFile(batch []ProcessedLog) {
	backupDir := "/var/log/wg-monitor"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		logger.Printf("创建备份目录失败: %v", err)
		return
	}

	filename := fmt.Sprintf("backup_%d.json", time.Now().Unix())
	fpath := filepath.Join(backupDir, filename)

	f, err := os.Create(fpath)
	if err != nil {
		logger.Printf("创建备份文件失败: %v", err)
		return
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(batch); err != nil {
		logger.Printf("写入备份文件失败: %v", err)
		return
	}

	logger.Printf("已备份 %d 条记录到 %s", len(batch), fpath)
}

// ================= SQLite 维护任务 =================

// startSQLiteMaintenance 定期执行 SQLite 维护（WAL checkpoint、ANALYZE、可选 VACUUM）
func startSQLiteMaintenance(ctx context.Context) {
	logger.Println("SQLite 维护任务已启动")
	defer logger.Println("SQLite 维护任务已停止")

	ticker := time.NewTicker(6 * time.Hour) // 每 6 小时维护一次
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			performSQLiteMaintenance(ctx)
		}
	}
}

// performSQLiteMaintenance 执行 SQLite 维护操作
func performSQLiteMaintenance(ctx context.Context) {
	mCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// 1. WAL checkpoint（将 WAL 合并回主数据库文件）
	if _, err := db.ExecContext(mCtx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		logger.Printf("WAL checkpoint 失败: %v", err)
	} else {
		logger.Println("WAL checkpoint 完成")
	}

	// 2. 更新统计信息（优化查询计划）
	if _, err := db.ExecContext(mCtx, "ANALYZE"); err != nil {
		logger.Printf("ANALYZE 失败: %v", err)
	}

	// 3. 条件 VACUUM：仅当空闲页占比 > 30% 时执行（减少 eMMC 写入）
	var pageCount, freePages int64
	if err := db.QueryRowContext(mCtx, "PRAGMA page_count").Scan(&pageCount); err == nil {
		if err := db.QueryRowContext(mCtx, "PRAGMA freelist_count").Scan(&freePages); err == nil {
			if pageCount > 0 {
				freeRatio := float64(freePages) / float64(pageCount)
				if freeRatio > 0.3 {
					logger.Printf("空闲页占比 %.1f%%，执行 VACUUM...", freeRatio*100)
					if _, err := db.ExecContext(mCtx, "VACUUM"); err != nil {
						logger.Printf("VACUUM 失败: %v", err)
					} else {
						logger.Println("VACUUM 完成")
					}
				}
			}
		}
	}
}

// ================= 数据降采样引擎 =================

// startDownsampler 定期将原始数据聚合到小时表，并清理已聚合的原始数据
// 策略：
//   - 最近 1 小时：保留原始 5 秒粒度
//   - >1 小时：聚合为小时粒度写入 traffic_hourly，删除 traffic_history 原始行
func startDownsampler(ctx context.Context) {
	logger.Println("数据降采样引擎已启动")
	defer logger.Println("数据降采样引擎已停止")

	ticker := time.NewTicker(15 * time.Minute) // 每 15 分钟执行一次降采样
	defer ticker.Stop()

	// 启动时立即执行一次
	downsample(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			downsample(ctx)
		}
	}
}

// downsample 将 >1 小时的原始数据聚合到 traffic_hourly 表，并删除已聚合的原始行
func downsample(ctx context.Context) {
	dsCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// 聚合边界：1 小时前的整点时间戳
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	boundaryTs := time.Date(oneHourAgo.Year(), oneHourAgo.Month(), oneHourAgo.Day(),
		oneHourAgo.Hour(), 0, 0, 0, oneHourAgo.Location()).Unix()

	tx, err := db.BeginTx(dsCtx, nil)
	if err != nil {
		logger.Printf("降采样事务开始失败: %v", err)
		return
	}
	defer tx.Rollback()

	// 1. 在事务内查询需要聚合的数据（确保事务原子性与一致性）
	rows, err := tx.QueryContext(dsCtx, `
		SELECT 
			(timestamp / 3600) * 3600 AS hour_ts,
			peer_public_key,
			AVG(rx_rate) AS avg_rx,
			AVG(tx_rate) AS avg_tx,
			MAX(rx_rate) AS max_rx,
			MAX(tx_rate) AS max_tx,
			MAX(rx_bytes) - MIN(rx_bytes) AS total_rx,
			MAX(tx_bytes) - MIN(tx_bytes) AS total_tx,
			AVG(is_online) * 100.0 AS online_pct,
			COUNT(*) AS cnt
		FROM traffic_history
		WHERE timestamp < ?
		GROUP BY hour_ts, peer_public_key
	`, boundaryTs)

	if err != nil {
		logger.Printf("降采样查询失败: %v", err)
		return
	}
	defer rows.Close()

	insertStmt, err := tx.PrepareContext(dsCtx, `
		INSERT OR REPLACE INTO traffic_hourly 
		(hour_ts, peer_key, avg_rx_rate, avg_tx_rate, max_rx_rate, max_tx_rate, 
		 total_rx, total_tx, online_pct, sample_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		logger.Printf("降采样 INSERT 准备失败: %v", err)
		return
	}
	defer insertStmt.Close()

	aggregatedCount := 0
	for rows.Next() {
		var hourTs int64
		var peerKey string
		var avgRx, avgTx, maxRx, maxTx, onlinePct float64
		var totalRx, totalTx, cnt int64

		if err := rows.Scan(&hourTs, &peerKey, &avgRx, &avgTx, &maxRx, &maxTx,
			&totalRx, &totalTx, &onlinePct, &cnt); err != nil {
			logger.Printf("降采样行扫描失败: %v", err)
			continue
		}

		// 修复负数（当 WG 接口重启导致计数器重置时）
		if totalRx < 0 {
			totalRx = 0
		}
		if totalTx < 0 {
			totalTx = 0
		}

		if _, err := insertStmt.ExecContext(dsCtx, hourTs, peerKey,
			math.Round(avgRx*1000)/1000, math.Round(avgTx*1000)/1000,
			math.Round(maxRx*1000)/1000, math.Round(maxTx*1000)/1000,
			totalRx, totalTx,
			math.Round(onlinePct*10)/10, cnt); err != nil {
			logger.Printf("降采样 INSERT 失败 [%s]: %v", peerKey, err)
			continue
		}
		aggregatedCount++
	}

	if aggregatedCount == 0 {
		return
	}

	// 删除已聚合的原始数据
	if _, err := tx.ExecContext(dsCtx, `DELETE FROM traffic_history WHERE timestamp < ?`, boundaryTs); err != nil {
		logger.Printf("降采样清理原始数据失败: %v", err)
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Printf("降采样事务提交失败: %v", err)
		return
	}

	logger.Printf("降采样完成: 聚合 %d 条小时记录，已清理 boundary=%d 之前的原始数据", aggregatedCount, boundaryTs)
}
