package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) string {
	testDir := filepath.Join(SandboxDataDir, "test_db")
	_ = os.MkdirAll(testDir, 0755)
	dbFile := filepath.Join(testDir, "test.db")
	_ = os.Remove(dbFile)

	DBPath = dbFile
	Retention = 30

	if err := initDB(); err != nil {
		t.Fatalf("initDB failed: %v", err)
	}
	return dbFile
}

func TestDatabase_InitAndTables(t *testing.T) {
	dbFile := setupTestDB(t)
	defer closeDB()
	defer os.Remove(dbFile)

	ctx := context.Background()

	// 验证插入与冲突更新 alias
	_, err := db.ExecContext(ctx, `
		INSERT INTO peer_aliases (public_key, alias, enabled) 
		VALUES (?, ?, ?) 
		ON CONFLICT(public_key) DO UPDATE SET alias = excluded.alias, enabled = excluded.enabled
	`, "testpk1234567890123456789012345678901234=", "Alice-Test", 1)
	if err != nil {
		t.Fatalf("insert alias failed: %v", err)
	}

	var alias string
	var enabled int
	err = db.QueryRowContext(ctx, "SELECT alias, enabled FROM peer_aliases WHERE public_key = ?", "testpk1234567890123456789012345678901234=").Scan(&alias, &enabled)
	if err != nil || alias != "Alice-Test" || enabled != 1 {
		t.Fatalf("expected alias 'Alice-Test' enabled 1, got '%s', %d, err=%v", alias, enabled, err)
	}

	// 更新别名
	_, err = db.ExecContext(ctx, `
		INSERT INTO peer_aliases (public_key, alias, enabled) 
		VALUES (?, ?, ?) 
		ON CONFLICT(public_key) DO UPDATE SET alias = excluded.alias, enabled = excluded.enabled
	`, "testpk1234567890123456789012345678901234=", "Alice-Updated", 0)
	if err != nil {
		t.Fatalf("update alias failed: %v", err)
	}

	err = db.QueryRowContext(ctx, "SELECT alias, enabled FROM peer_aliases WHERE public_key = ?", "testpk1234567890123456789012345678901234=").Scan(&alias, &enabled)
	if err != nil || alias != "Alice-Updated" || enabled != 0 {
		t.Fatalf("expected alias 'Alice-Updated' enabled 0, got '%s', %d, err=%v", alias, enabled, err)
	}
}

func TestDatabase_BatchFlushAndArchive(t *testing.T) {
	dbFile := setupTestDB(t)
	defer closeDB()
	defer os.Remove(dbFile)

	now := time.Now().Unix()
	fourDaysAgo := now - 4*86400

	// 插入一批较新的记录和一批较旧的记录
	var batch []ProcessedLog
	for i := 0; i < 5; i++ {
		batch = append(batch, ProcessedLog{
			Timestamp: now - int64(i*10),
			PublicKey: "test_pk_recent",
			Endpoint:  "198.51.100.1:51820",
			RxBytes:   1000 + int64(i*100),
			TxBytes:   2000 + int64(i*200),
			RxRate:    1.5,
			TxRate:    2.5,
			IsOnline:  true,
		})
	}

	for i := 0; i < 5; i++ {
		batch = append(batch, ProcessedLog{
			Timestamp: fourDaysAgo + int64(i*10),
			PublicKey: "test_pk_old",
			Endpoint:  "198.51.100.2:51820",
			RxBytes:   5000 + int64(i*100),
			TxBytes:   6000 + int64(i*200),
			RxRate:    0.8,
			TxRate:    1.2,
			IsOnline:  true,
		})
	}

	// 测试批量刷入
	flushDB(batch)

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM traffic_history").Scan(&count)
	if count != 10 {
		t.Fatalf("expected 10 records in traffic_history, got %d", count)
	}

	// 执行数据归档与清理（应将 4 天前的数据归档并从 traffic_history 删除）
	cleanOldData(context.Background())

	var recentCount, archiveCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM traffic_history").Scan(&recentCount)
	_ = db.QueryRow("SELECT COUNT(*) FROM traffic_hourly").Scan(&archiveCount)

	if recentCount != 5 {
		t.Errorf("expected 5 recent records to remain, got %d", recentCount)
	}
	if archiveCount == 0 {
		t.Errorf("expected archived records in traffic_hourly, got %d", archiveCount)
	}
}
