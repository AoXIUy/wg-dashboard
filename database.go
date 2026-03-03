package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ================= 数据库初始化 =================

// initDB 连接 MySQL，设置连接池参数，创建所有必要的表和迁移
func initDB() error {
	var err error
	db, err = sql.Open("mysql", MySQLDSN)
	if err != nil {
		return fmt.Errorf("打开数据库连接失败: %w", err)
	}

	// 优化连接池参数
	db.SetMaxOpenConns(DBMaxOpenConns)
	db.SetMaxIdleConns(DBMaxIdleConns)
	db.SetConnMaxLifetime(DBConnMaxLifetime)
	db.SetConnMaxIdleTime(DBConnMaxIdleTime)

	// 健康检查
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("数据库连接测试失败: %w", err)
	}

	// 创建表 1: traffic_history
	schema1 := `
	CREATE TABLE IF NOT EXISTS traffic_history (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		timestamp BIGINT UNSIGNED NOT NULL,
		peer_public_key CHAR(44) NOT NULL,
		endpoint VARCHAR(64) DEFAULT '',
		rx_bytes BIGINT UNSIGNED NOT NULL,
		tx_bytes BIGINT UNSIGNED NOT NULL,
		rx_rate REAL DEFAULT 0,
		tx_rate REAL DEFAULT 0,
		is_online TINYINT(1) DEFAULT 0,
		INDEX idx_peer_time (peer_public_key, timestamp),
		INDEX idx_time (timestamp)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`

	if _, err = db.ExecContext(ctx, schema1); err != nil {
		return fmt.Errorf("创建 traffic_history 表失败: %w", err)
	}

	// 创建表 2: peer_aliases
	schema2 := `
	CREATE TABLE IF NOT EXISTS peer_aliases (
		public_key CHAR(44) PRIMARY KEY,
		alias TEXT NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`

	if _, err = db.ExecContext(ctx, schema2); err != nil {
		return fmt.Errorf("创建 peer_aliases 表失败: %w", err)
	}

	// 迁移: 为 peer_aliases 添加 enabled 字段（若不存在）
	_, err = db.ExecContext(ctx, `ALTER TABLE peer_aliases ADD COLUMN IF NOT EXISTS enabled TINYINT(1) NOT NULL DEFAULT 1`)
	if err != nil {
		logger.Printf("迁移 peer_aliases.enabled 字段失败（可能版本不支持 IF NOT EXISTS）: %v", err)
		// 尝试兼容旧版本 MySQL 的方式：忽略 duplicate column 错误
		_, _ = db.ExecContext(ctx, `ALTER TABLE peer_aliases ADD COLUMN enabled TINYINT(1) NOT NULL DEFAULT 1`)
	}

	// 创建表 3: peer_configs（存储禁用 peer 的完整配置块，用于内核层禁用/启用）
	schema3 := `
	CREATE TABLE IF NOT EXISTS peer_configs (
		public_key  CHAR(44) PRIMARY KEY,
		conf_name   VARCHAR(64) NOT NULL,
		peer_block  TEXT        NOT NULL,
		saved_at    BIGINT      NOT NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`

	if _, err = db.ExecContext(ctx, schema3); err != nil {
		return fmt.Errorf("创建 peer_configs 表失败: %w", err)
	}

	logger.Println("数据库初始化成功")

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

// cleanOldData 删除超出保留期的历史流量记录
func cleanOldData(ctx context.Context) {
	expireTime := time.Now().AddDate(0, 0, -Retention).Unix()

	cleanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := db.ExecContext(cleanCtx, `DELETE FROM traffic_history WHERE timestamp < ?`, expireTime)
	if err != nil {
		logger.Printf("清理旧数据失败: %v", err)
		return
	}

	if rows, err := result.RowsAffected(); err == nil && rows > 0 {
		logger.Printf("已清理 %d 条旧数据记录", rows)
	}
}

// ================= 异步写入 =================

// startAsyncWriter 定时将内存缓冲中的流量日志批量写入 MySQL
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
				flushMySQL(batch)
			}
			return
		case <-ticker.C:
			if batch := trafficBuffer.Flush(); batch != nil {
				flushMySQL(batch)
			}
		}
	}
}

// flushMySQL 将一批日志写入 MySQL，失败时重试并回退到文件
func flushMySQL(batch []ProcessedLog) {
	if len(batch) == 0 {
		return
	}

	for attempt := 0; attempt < MaxRetries; attempt++ {
		err := attemptFlushMySQL(batch)
		if err == nil {
			return
		}

		logger.Printf("MySQL 写入失败 (尝试 %d/%d): %v", attempt+1, MaxRetries, err)
		metrics.IncFailedWrites()

		if attempt < MaxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	// 最终失败，备份到本地文件
	backupToFile(batch)
}

// attemptFlushMySQL 使用事务批量插入，部分行失败时备份失败条目
func attemptFlushMySQL(batch []ProcessedLog) error {
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

	// 正确性修复：收集失败条目，事务提交后备份，避免静默丢失
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
			logEntry.IsOnline,
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
