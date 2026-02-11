package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"wg-dashboard/pkg/config"
	"wg-dashboard/pkg/models"
)

var (
	DB           *sql.DB
	RDB          *redis.Client
	RedisEnabled bool
)

// InitDB 初始化 MySQL
func InitDB(dsn string) error {
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	DB.SetMaxOpenConns(config.DBMaxOpenConns)
	DB.SetMaxIdleConns(config.DBMaxIdleConns)
	DB.SetConnMaxLifetime(config.DBConnMaxLifetime)

	// 建表
	schemaTraffic := `
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
    );`

	schemaAliases := `
    CREATE TABLE IF NOT EXISTS peer_aliases (
        public_key CHAR(44) PRIMARY KEY,
        alias TEXT NOT NULL
    );`

	if _, err = DB.Exec(schemaTraffic); err != nil {
		return fmt.Errorf("创建 traffic_history 表失败: %v", err)
	}

	if _, err = DB.Exec(schemaAliases); err != nil {
		return fmt.Errorf("创建 peer_aliases 表失败: %v", err)
	}

	return nil
}

// InitRedis 初始化 Redis
func InitRedis(addr string) {
	RDB = redis.NewClient(&redis.Options{
		Addr: addr,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := RDB.Ping(ctx).Err(); err != nil {
		log.Printf("Redis 连接失败: %v (将禁用缓存/队列功能)", err)
		RedisEnabled = false
	} else {
		log.Println("Redis 已连接")
		RedisEnabled = true
	}
}

// Close 关闭数据库连接
func Close() {
	if DB != nil {
		DB.Close()
	}
	if RDB != nil {
		RDB.Close()
	}
}

// GetAliases 获取所有别名
func GetAliases() (map[string]string, error) {
	aliasMap := make(map[string]string)
	rows, err := DB.Query("SELECT public_key, alias FROM peer_aliases")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pk, a string
		if err := rows.Scan(&pk, &a); err != nil {
			continue
		}
		aliasMap[pk] = a
	}
	return aliasMap, nil
}

// SaveAlias 保存别名
func SaveAlias(publicKey, alias string) error {
	_, err := DB.Exec(`INSERT INTO peer_aliases (public_key, alias) VALUES (?, ?) ON DUPLICATE KEY UPDATE alias = VALUES(alias)`, publicKey, alias)
	return err
}

// DeleteAlias 删除别名
func DeleteAlias(publicKey string) error {
	_, err := DB.Exec(`DELETE FROM peer_aliases WHERE public_key = ?`, publicKey)
	return err
}

// BulkInsertTrafficHistory 批量插入流量历史
func BulkInsertTrafficHistory(batch []models.ProcessedLog) error {
	if len(batch) == 0 {
		return nil
	}

	query := "INSERT INTO traffic_history (timestamp, peer_public_key, endpoint, rx_bytes, tx_bytes, rx_rate, tx_rate, is_online) VALUES "
	vals := []interface{}{}

	for _, row := range batch {
		query += "(?, ?, ?, ?, ?, ?, ?, ?),"
		vals = append(vals, row.Timestamp, row.PublicKey, row.Endpoint, row.RxBytes, row.TxBytes, row.RxRate, row.TxRate, row.IsOnline)
	}

	query = query[:len(query)-1]

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(vals...); err != nil {
		return err
	}

	return tx.Commit()
}

// CleanOldData 清理旧数据
func CleanOldData(retentionDays int) (int64, error) {
	expireTime := time.Now().AddDate(0, 0, -retentionDays).Unix()
	result, err := DB.Exec(`DELETE FROM traffic_history WHERE timestamp < ?`, expireTime)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetPeerHistoryQuery 获取历史查询 Rows
func GetPeerHistoryQuery(pk string, startTime int64) (*sql.Rows, error) {
	return DB.Query(`SELECT timestamp, rx_rate, tx_rate FROM traffic_history WHERE peer_public_key = ? AND timestamp >= ? ORDER BY timestamp ASC`, pk, startTime)
}

// GetTrafficChartDataQuery 获取流量图表数据 Rows
func GetTrafficChartDataQuery(startTime int64) (*sql.Rows, error) {
	return DB.Query(`SELECT timestamp, SUM(rx_rate), SUM(tx_rate) FROM traffic_history WHERE timestamp >= ? GROUP BY timestamp ORDER BY timestamp ASC`, startTime)
}

// GetAccessLogsQuery 获取访问日志 Rows
func GetAccessLogsQuery(pk string, since int64) (*sql.Rows, error) {
	query := `
        SELECT timestamp, endpoint, rx_bytes, tx_bytes
        FROM traffic_history 
        WHERE peer_public_key = ? 
          AND endpoint != '' 
          AND timestamp > ?
        ORDER BY timestamp ASC
    `
	return DB.Query(query, pk, since)
}

// GetAnalysisDataQuery 获取分析数据 Rows
func GetAnalysisDataQuery(ctx context.Context, startTime int64) (*sql.Rows, error) {
	q := `SELECT peer_public_key, COUNT(*), SUM(is_online), SUM(rx_rate), SUM(tx_rate), MAX(timestamp) 
		    FROM traffic_history WHERE timestamp > ? GROUP BY peer_public_key`
	return DB.QueryContext(ctx, q, startTime)
}

// GetHourlyProfileQuery 获取每小时数据 Rows
func GetHourlyProfileQuery(ctx context.Context, startTime int64) (*sql.Rows, error) {
	hQuery := `SELECT timestamp, SUM(rx_rate + tx_rate) FROM traffic_history 
			   WHERE timestamp > ? GROUP BY timestamp`
	return DB.QueryContext(ctx, hQuery, startTime)
}

// UpdateRedisPeerState 更新 Redis 中的 Peer 状态
func UpdateRedisPeerState(ctx context.Context, pk string, data map[string]interface{}) {
	if !RedisEnabled || RDB == nil {
		return
	}
	key := fmt.Sprintf("wg:peer:state:%s", pk)
	RDB.HSet(ctx, key, data)
	RDB.Expire(ctx, key, 5*time.Minute)
}

// GetRedisPeerState 获取 Redis 中的 Peer 状态
func GetRedisPeerState(ctx context.Context, pk string) (map[string]string, error) {
	if !RedisEnabled || RDB == nil {
		return nil, fmt.Errorf("redis disabled")
	}
	return RDB.HGetAll(ctx, fmt.Sprintf("wg:peer:state:%s", pk)).Result()
}

// PublishBroadcast 发布广播消息
func PublishBroadcast(ctx context.Context, update models.DashboardUpdate) {
	if !RedisEnabled || RDB == nil {
		return
	}
	jsonData, _ := json.Marshal(update)
	RDB.Publish(ctx, "wg:channel:broadcast", string(jsonData))
}

// SubscribeBroadcast 订阅广播消息
func SubscribeBroadcast(ctx context.Context) *redis.PubSub {
	if !RedisEnabled || RDB == nil {
		return nil
	}
	return RDB.Subscribe(ctx, "wg:channel:broadcast")
}

// SetCache 设置缓存
func SetCache(ctx context.Context, key string, value interface{}, ttl time.Duration) {
	if !RedisEnabled || RDB == nil {
		return
	}
	jsonBytes, _ := json.Marshal(value)
	RDB.Set(ctx, key, jsonBytes, ttl)
}

// GetCache 获取缓存
func GetCache(ctx context.Context, key string, dest interface{}) error {
	if !RedisEnabled || RDB == nil {
		return fmt.Errorf("redis disabled")
	}
	val, err := RDB.Get(ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), dest)
}
