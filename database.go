package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ================= 数据库初始化 =================

var DBPath string

// initDB 初始化纯 Go SQLite 内嵌数据库，设置 WAL 模式与连接池参数，创建/迁移表结构
func initDB() error {
	if DBPath == "" {
		if v := os.Getenv("WG_DB_PATH"); v != "" {
			DBPath = v
		} else {
			DBPath = filepath.Join(SandboxDataDir, "wg_dashboard.db")
		}
	}

	// 确保父目录存在
	if err := os.MkdirAll(filepath.Dir(DBPath), 0755); err != nil {
		return fmt.Errorf("创建数据库存储目录失败: %w", err)
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=auto_vacuum(INCREMENTAL)", DBPath)
	var err error
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("打开内嵌 SQLite 数据库连接失败: %w", err)
	}

	// SQLite WAL 模式连接池优化
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(DBConnMaxLifetime)
	db.SetConnMaxIdleTime(DBConnMaxIdleTime)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("数据库连接测试失败: %w", err)
	}

	// 表 1: traffic_history (主流量历史表)
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
	CREATE INDEX IF NOT EXISTS idx_time ON traffic_history (timestamp);
	`
	if _, err = db.ExecContext(ctx, schema1); err != nil {
		return fmt.Errorf("创建 traffic_history 表失败: %w", err)
	}

	// 表 2: peer_aliases (客户端别名与启用标记表)
	schema2 := `
	CREATE TABLE IF NOT EXISTS peer_aliases (
		public_key TEXT PRIMARY KEY,
		alias TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1
	);
	`
	if _, err = db.ExecContext(ctx, schema2); err != nil {
		return fmt.Errorf("创建 peer_aliases 表失败: %w", err)
	}

	// 表 3: peer_configs (客户端禁用备份块表)
	schema3 := `
	CREATE TABLE IF NOT EXISTS peer_configs (
		public_key TEXT PRIMARY KEY,
		conf_name TEXT NOT NULL,
		peer_block TEXT NOT NULL,
		saved_at INTEGER NOT NULL
	);
	`
	if _, err = db.ExecContext(ctx, schema3); err != nil {
		return fmt.Errorf("创建 peer_configs 表失败: %w", err)
	}

	// 表 4: traffic_hourly (历史流量降采样归档表，用于长周期轻量存储)
	schema4 := `
	CREATE TABLE IF NOT EXISTS traffic_hourly (
		timestamp INTEGER NOT NULL,
		peer_public_key TEXT NOT NULL,
		rx_bytes INTEGER NOT NULL,
		tx_bytes INTEGER NOT NULL,
		rx_rate REAL DEFAULT 0,
		tx_rate REAL DEFAULT 0,
		PRIMARY KEY (peer_public_key, timestamp)
	);
	CREATE INDEX IF NOT EXISTS idx_hourly_time ON traffic_hourly (timestamp);
	`
	if _, err = db.ExecContext(ctx, schema4); err != nil {
		return fmt.Errorf("创建 traffic_hourly 降采样表失败: %w", err)
	}

	logger.Printf("内嵌 SQLite 数据库初始化成功 (文件: %s, 模式: WAL)", DBPath)

	// 初始化分析引擎
	analysisEngine = NewAnalysisEngine(db)

	return nil
}

// closeDB 关闭数据库连接和 GeoIP 提供器
func closeDB() {
	if db != nil {
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

// ================= 数据归档与清理 =================

// startCleaner 启动定时清理任务，每 24 小时执行历史流量数据的自动归档、降采样与过期清理
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

// cleanOldData 对超过 3 天的历史流量降采样归档到 traffic_hourly，并彻底删除超过 Retention 天的历史数据
func cleanOldData(ctx context.Context) {
	now := time.Now()
	expireTime := now.AddDate(0, 0, -Retention).Unix()
	downsampleThreshold := now.AddDate(0, 0, -3).Unix()

	cleanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// 1. 降采样归档：将 3 天前至 Retention 天内的 6s 级高频记录聚合成每小时 1 条归档记录
	archiveQuery := `
	INSERT OR IGNORE INTO traffic_hourly (timestamp, peer_public_key, rx_bytes, tx_bytes, rx_rate, tx_rate)
	SELECT 
		(timestamp / 3600) * 3600 as hour_ts,
		peer_public_key,
		MAX(rx_bytes),
		MAX(tx_bytes),
		AVG(rx_rate),
		AVG(tx_rate)
	FROM traffic_history
	WHERE timestamp < ? AND timestamp >= ?
	GROUP BY peer_public_key, hour_ts;
	`
	if _, err := db.ExecContext(cleanCtx, archiveQuery, downsampleThreshold, expireTime); err != nil {
		logger.Printf("降采样归档历史数据失败: %v", err)
	}

	// 2. 清理已归档的旧高频记录（保留最近 3 天的高频秒级记录）
	delArchivedQuery := `DELETE FROM traffic_history WHERE timestamp < ?`
	if res, err := db.ExecContext(cleanCtx, delArchivedQuery, downsampleThreshold); err == nil {
		if rows, _ := res.RowsAffected(); rows > 0 {
			logger.Printf("已清理并归档 %d 条秒级高频流量记录", rows)
		}
	}

	// 3. 彻底删除超出保留期限的归档记录
	delExpiredQuery := `DELETE FROM traffic_hourly WHERE timestamp < ?`
	if res, err := db.ExecContext(cleanCtx, delExpiredQuery, expireTime); err == nil {
		if rows, _ := res.RowsAffected(); rows > 0 {
			logger.Printf("已清理 %d 条超出 %d 天保留期的归档流量记录", rows, Retention)
		}
	}

	// 4. 定期执行增量空间回收与查询计划优化
	_, _ = db.ExecContext(cleanCtx, `PRAGMA incremental_vacuum;`)
	_, _ = db.ExecContext(cleanCtx, `PRAGMA optimize;`)
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
				flushDB(batch)
			}
			return
		case <-ticker.C:
			if batch := trafficBuffer.Flush(); batch != nil {
				flushDB(batch)
			}
		}
	}
}

// flushDB 将一批日志写入 SQLite 数据库，失败时重试并回退到本地沙盒文件
func flushDB(batch []ProcessedLog) {
	if len(batch) == 0 {
		return
	}

	for attempt := 0; attempt < MaxRetries; attempt++ {
		err := attemptFlushDB(batch)
		if err == nil {
			return
		}

		logger.Printf("SQLite 批量写入失败 (尝试 %d/%d): %v", attempt+1, MaxRetries, err)
		metrics.IncFailedWrites()

		if attempt < MaxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
		}
	}

	// 最终失败，备份到本地沙盒目录
	backupToFile(batch)
}

// attemptFlushDB 使用事务批量插入
func attemptFlushDB(batch []ProcessedLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	for _, logEntry := range batch {
		onlineVal := 0
		if logEntry.IsOnline {
			onlineVal = 1
		}
		if _, err := stmt.ExecContext(ctx,
			logEntry.Timestamp,
			logEntry.PublicKey,
			logEntry.Endpoint,
			logEntry.RxBytes,
			logEntry.TxBytes,
			logEntry.RxRate,
			logEntry.TxRate,
			onlineVal,
		); err != nil {
			logger.Printf("插入记录失败 [%s]: %v", logEntry.PublicKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

// backupToFile 将写库失败的记录以 JSON 格式备份到沙盒目录，绝不污染宿主机系统目录
func backupToFile(batch []ProcessedLog) {
	backupDir := SandboxBackupsDir
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
