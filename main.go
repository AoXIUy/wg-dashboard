package main

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	_ "modernc.org/sqlite"
)

//go:embed index.html
var indexHtml string

// ================= 常量定义 =================
const (
	CollectInterval     = 2 * time.Second
	WriteInterval       = 6 * time.Second
	BatchSize           = 10
	MaxAliasLength      = 100
	MaxPublicKeyLength  = 200
	OnlineThreshold     = 3 * time.Minute
	DBMaxOpenConns      = 25
	DBMaxIdleConns      = 5
	DBConnMaxLifetime   = 5 * time.Minute
	CacheTTL            = 10 * time.Minute
	ShutdownTimeout     = 30 * time.Second
	BitsPerByte         = 8.0
	MegabitsPerSecond   = 1000000.0
	TokenExpireDuration = 24 * time.Hour
)

// ================= 配置区域 =================
var (
	WGInterface   string
	ServerPort    string
	DBPath        string
	Retention     int
	AdminPassword string
	JWTSecret     string
)

// ================= 数据结构 =================

type RawSnapshot struct {
	Timestamp time.Time
	Peers     []wgtypes.Peer
}

type ProcessedLog struct {
	Timestamp int64
	PublicKey string
	RxBytes   int64
	TxBytes   int64
	RxRate    float64
	TxRate    float64
	IsOnline  bool
}

type PeerData struct {
	PublicKey     string    `json:"public_key"`
	AllowedIPs    []string  `json:"allowed_ips"`
	Endpoint      string    `json:"endpoint"`
	LastHandshake time.Time `json:"last_handshake"`
	ReceiveBytes  int64     `json:"receive_bytes"`
	TransmitBytes int64     `json:"transmit_bytes"`
	Alias         string    `json:"alias"`
	RxRate        float64   `json:"rx_rate"`
	TxRate        float64   `json:"tx_rate"`
	IsOnline      bool      `json:"is_online"`
}

type PeerState struct {
	LastRx   int64
	LastTx   int64
	LastSeen time.Time
}

type SystemInfo struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	CPUTemp    float64 `json:"cpu_temp"`
	Uptime     uint64  `json:"uptime"`
	HostName   string  `json:"hostname"`
	OS         string  `json:"os"`
}

type cacheEntry struct {
	data      ProcessedLog
	timestamp time.Time
}

// --- 鉴权结构 ---
type LoginRequest struct {
	Password string `json:"password" binding:"required"`
}

type JwtClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

// --- 分析结构 ---
type PeerAnalysis struct {
	PublicKey    string  `json:"public_key"`
	Alias        string  `json:"alias"`
	TotalRx      int64   `json:"total_rx"`       // 估算的总下载字节
	TotalTx      int64   `json:"total_tx"`       // 估算的总上传字节
	Uptime       float64 `json:"uptime_percent"` // 在线率 0-100
	HealthScore  int     `json:"health_score"`   // 健康分 0-100
	LastSeenTime int64   `json:"last_seen_time"`
}

type ActivityPoint struct {
	Hour  int     `json:"hour"`   // 0-23
	RxSum float64 `json:"rx_sum"` // 聚合速率指标
	TxSum float64 `json:"tx_sum"`
}

type AnalysisReport struct {
	Period        string          `json:"period"`
	GeneratedAt   int64           `json:"generated_at"`
	Peers         []PeerAnalysis  `json:"peers"`
	HourlyProfile []ActivityPoint `json:"hourly_profile"`
}

// ================= 全局变量 =================
var (
	db               *sql.DB
	latestPeersCache sync.Map
	publicKeyRegex   = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	logger           *log.Logger
)

func main() {
	logger = log.New(os.Stdout, "[WG-Monitor] ", log.LstdFlags|log.Lshortfile)

	flag.StringVar(&WGInterface, "iface", "wg0", "WireGuard 接口名称")
	flag.StringVar(&ServerPort, "port", ":8080", "Web 监听端口")
	flag.StringVar(&DBPath, "db", "./wg_stats.db", "数据库路径")
	flag.IntVar(&Retention, "days", 30, "数据保留天数")
	flag.StringVar(&AdminPassword, "password", "admin123", "仪表盘访问密码")
	flag.StringVar(&JWTSecret, "secret", "change_this_secret_in_prod", "JWT 签名密钥")
	flag.Parse()

	if err := initDB(); err != nil {
		logger.Fatalf("数据库初始化失败: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Printf("数据库关闭失败: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rawChan := make(chan RawSnapshot, 20)
	writeChan := make(chan []ProcessedLog, 10)

	var wg sync.WaitGroup

	// 启动完整 Pipeline 组件
	wg.Add(1)
	go func() {
		defer wg.Done()
		startCollector(ctx, rawChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startProcessor(ctx, rawChan, writeChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startWriter(ctx, writeChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startCleaner(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startCacheCleaner(ctx)
	}()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// 静态页面 (公开)
	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, indexHtml)
	})

	api := r.Group("/api")
	{
		// 公开接口
		api.POST("/login", loginHandler)
		api.GET("/check_auth", func(c *gin.Context) {
			tokenString := extractToken(c)
			if tokenString == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"status": "invalid"})
				return
			}
			token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(JWTSecret), nil
			})
			if err != nil || !token.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"status": "invalid"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// 受保护接口
		authorized := api.Group("/")
		authorized.Use(authMiddleware())
		{
			authorized.GET("/peers", getPeers)
			authorized.GET("/history/:publickey", getPeerHistory)
			authorized.GET("/stats", getStats)
			authorized.POST("/alias", setAlias)
			authorized.GET("/chart/traffic", getTrafficChartData)
			authorized.GET("/system", getSystemStatus)
			
			// 深度分析接口
			authorized.GET("/analysis", func(c *gin.Context) {
				daysStr := c.DefaultQuery("days", "7")
				days := 7
				if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
					days = d
				}

				report, err := getAnalysisData(days)
				if err != nil {
					logger.Printf("分析生成失败: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "分析生成失败"})
					return
				}
				c.JSON(http.StatusOK, report)
			})
		}
	}

	srv := &http.Server{
		Addr:    ServerPort,
		Handler: r,
	}

	go func() {
		logger.Printf("==============================================")
		logger.Printf("WireGuard Monitor 启动成功")
		logger.Printf("接口: %s | 端口: %s", WGInterface, ServerPort)
		logger.Printf("数据库: %s | 保留天数: %d", DBPath, Retention)
		logger.Printf("安全: 已启用 JWT 鉴权")
		logger.Printf("==============================================")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("HTTP 服务器启动失败: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Println("开始优雅关闭...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("HTTP 服务器关闭失败: %v", err)
	}
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Println("所有后台任务已停止")
	case <-time.After(ShutdownTimeout):
		logger.Println("后台任务关闭超时")
	}
	logger.Println("程序已退出")
}

// ================= 安全鉴权逻辑 =================

func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}
	return ""
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("无效的签名方法")
			}
			return []byte(JWTSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效或过期的令牌"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}

	if req.Password != AdminPassword {
		time.Sleep(500 * time.Millisecond)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}

	expirationTime := time.Now().Add(TokenExpireDuration)
	claims := &JwtClaims{
		User: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "wg-monitor",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_at": expirationTime.Unix(),
	})
}

// ================= 数据库与分析逻辑 =================

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", DBPath)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(DBMaxOpenConns)
	db.SetMaxIdleConns(DBMaxIdleConns)
	db.SetConnMaxLifetime(DBConnMaxLifetime)

	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA temp_store = MEMORY",
	}
	for _, pragma := range pragmas {
		db.Exec(pragma)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS traffic_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL, 
		peer_public_key TEXT NOT NULL,
		rx_bytes INTEGER NOT NULL,
		tx_bytes INTEGER NOT NULL,
		rx_rate REAL DEFAULT 0,
		tx_rate REAL DEFAULT 0,
		is_online BOOLEAN DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_peer_time ON traffic_history(peer_public_key, timestamp);
	CREATE INDEX IF NOT EXISTS idx_time ON traffic_history(timestamp);

	CREATE TABLE IF NOT EXISTS peer_aliases (
		public_key TEXT PRIMARY KEY,
		alias TEXT NOT NULL
	);
	`
	_, err = db.Exec(schema)
	return err
}

func getAnalysisData(days int) (*AnalysisReport, error) {
	startTime := time.Now().AddDate(0, 0, -days).Unix()
	report := &AnalysisReport{
		Period:      fmt.Sprintf("Last %d Days", days),
		GeneratedAt: time.Now().Unix(),
	}

	aliasMap := make(map[string]string)
	aRows, err := db.Query("SELECT public_key, alias FROM peer_aliases")
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var pk, a string
			aRows.Scan(&pk, &a)
			aliasMap[pk] = a
		}
	}

	// 聚合 Peer 统计
	queryPeers := `
		SELECT 
			peer_public_key,
			COUNT(*) as samples,
			TOTAL(is_online) as online_samples,
			TOTAL(rx_rate) as sum_rx_rate,
			TOTAL(tx_rate) as sum_tx_rate,
			MAX(timestamp) as last_seen
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY peer_public_key
	`
	rows, err := db.Query(queryPeers, startTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var pk string
		var samples, onlineSamples int64
		var sumRx, sumTx float64
		var lastSeen int64

		if err := rows.Scan(&pk, &samples, &onlineSamples, &sumRx, &sumTx, &lastSeen); err != nil {
			continue
		}

		if samples == 0 {
			samples = 1
		}

		// 估算流量 (基于 6秒采样周期)
		const secondsPerSample = 6.0
		estRx := int64(sumRx * secondsPerSample * 1000000 / 8)
		estTx := int64(sumTx * secondsPerSample * 1000000 / 8)

		uptime := float64(onlineSamples) / float64(samples) * 100.0

		score := int(uptime)
		if lastSeen < time.Now().Add(-24*time.Hour).Unix() {
			score -= 20
		}
		if score < 0 {
			score = 0
		}

		report.Peers = append(report.Peers, PeerAnalysis{
			PublicKey:    pk,
			Alias:        aliasMap[pk],
			TotalRx:      estRx,
			TotalTx:      estTx,
			Uptime:       uptime,
			HealthScore:  score,
			LastSeenTime: lastSeen,
		})
	}

	sort.Slice(report.Peers, func(i, j int) bool {
		return (report.Peers[i].TotalRx + report.Peers[i].TotalTx) > (report.Peers[j].TotalRx + report.Peers[j].TotalTx)
	})

	// 聚合 24h 画像
	queryTime := `
		SELECT timestamp, SUM(rx_rate + tx_rate)
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY timestamp / 3600
	`
	tRows, err := db.Query(queryTime, startTime)
	if err != nil {
		return nil, err
	}
	defer tRows.Close()

	hourlyMap := make(map[int]float64)
	hourlyCount := make(map[int]int)

	for tRows.Next() {
		var ts int64
		var rateSum float64
		tRows.Scan(&ts, &rateSum)

		t := time.Unix(ts, 0)
		h := t.Hour()
		hourlyMap[h] += rateSum
		hourlyCount[h]++
	}

	for i := 0; i < 24; i++ {
		avgRate := 0.0
		if c := hourlyCount[i]; c > 0 {
			avgRate = hourlyMap[i] / float64(c)
		}
		report.HourlyProfile = append(report.HourlyProfile, ActivityPoint{
			Hour:  i,
			RxSum: avgRate,
		})
	}

	return report, nil
}

// ================= Pipeline 核心 (完整版) =================

func startCollector(ctx context.Context, out chan<- RawSnapshot) {
	logger.Println("采集器已启动")
	defer logger.Println("采集器已停止")

	var client *wgctrl.Client
	var err error
	
	reconnect := func() error {
		if client != nil {
			client.Close()
		}
		client, err = wgctrl.New()
		if err != nil {
			logger.Printf("WireGuard 连接失败: %v", err)
			return err
		}
		logger.Println("WireGuard 客户端连接成功")
		return nil
	}

	if err := reconnect(); err != nil {
		logger.Printf("初始连接失败，将在后续重试")
	}

	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if client != nil {
				client.Close()
			}
			close(out)
			return
		case <-ticker.C:
			if client == nil {
				if err := reconnect(); err != nil {
					continue
				}
			}

			device, err := client.Device(WGInterface)
			if err != nil {
				logger.Printf("获取设备信息失败: %v", err)
				reconnect()
				continue
			}

			select {
			case out <- RawSnapshot{Timestamp: time.Now(), Peers: device.Peers}:
			case <-ctx.Done():
				if client != nil {
					client.Close()
				}
				close(out)
				return
			default:
				// 通道满时丢弃数据，防止阻塞
			}
		}
	}
}

func startProcessor(ctx context.Context, in <-chan RawSnapshot, out chan<- []ProcessedLog) {
	logger.Println("处理器已启动")
	defer logger.Println("处理器已停止")

	stateMap := make(map[string]*PeerState)
	var buffer []ProcessedLog
	flushTicker := time.NewTicker(WriteInterval)
	defer flushTicker.Stop()

	flush := func() {
		if len(buffer) == 0 {
			return
		}

		batch := make([]ProcessedLog, len(buffer))
		copy(batch, buffer)
		
		select {
		case out <- batch:
			buffer = buffer[:0]
		case <-ctx.Done():
			return
		default:
			logger.Printf("警告: 写入通道已满，缓冲区大小: %d", len(buffer))
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			close(out)
			return

		case snap, ok := <-in:
			if !ok {
				flush()
				close(out)
				return
			}

			for _, p := range snap.Peers {
				pk := p.PublicKey.String()
				state, exists := stateMap[pk]
				
				if !exists {
					state = &PeerState{
						LastRx:   p.ReceiveBytes,
						LastTx:   p.TransmitBytes,
						LastSeen: snap.Timestamp,
					}
					stateMap[pk] = state
				}

				timeDiff := snap.Timestamp.Sub(state.LastSeen).Seconds()
				var rxRate, txRate float64

				if timeDiff > 0 {
					if p.ReceiveBytes >= state.LastRx {
						rxRate = float64(p.ReceiveBytes-state.LastRx) * BitsPerByte / timeDiff / MegabitsPerSecond
					}
					if p.TransmitBytes >= state.LastTx {
						txRate = float64(p.TransmitBytes-state.LastTx) * BitsPerByte / timeDiff / MegabitsPerSecond
					}
				}

				isOnline := !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < OnlineThreshold

				state.LastRx = p.ReceiveBytes
				state.LastTx = p.TransmitBytes
				state.LastSeen = snap.Timestamp

				logEntry := ProcessedLog{
					Timestamp: snap.Timestamp.Unix(),
					PublicKey: pk,
					RxBytes:   p.ReceiveBytes,
					TxBytes:   p.TransmitBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					IsOnline:  isOnline,
				}
				
				buffer = append(buffer, logEntry)
				latestPeersCache.Store(pk, cacheEntry{
					data:      logEntry,
					timestamp: time.Now(),
				})
			}

			if len(buffer) >= BatchSize {
				flush()
			}

		case <-flushTicker.C:
			flush()
		}
	}
}

func startWriter(ctx context.Context, in <-chan []ProcessedLog) {
	logger.Println("写入器已启动")
	defer logger.Println("写入器已停止")

	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-in:
			if !ok {
				return
			}

			if len(batch) == 0 {
				continue
			}

			if err := writeBatch(batch); err != nil {
				logger.Printf("批量写入失败 (大小: %d): %v", len(batch), err)
			}
		}
	}
}

func writeBatch(batch []ProcessedLog) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO traffic_history 
		(timestamp, peer_public_key, rx_bytes, tx_bytes, rx_rate, tx_rate, is_online) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, logEntry := range batch {
		if _, err := stmt.Exec(
			logEntry.Timestamp,
			logEntry.PublicKey,
			logEntry.RxBytes,
			logEntry.TxBytes,
			logEntry.RxRate,
			logEntry.TxRate,
			logEntry.IsOnline,
		); err != nil {
			logger.Printf("插入记录失败 (peer: %s): %v", logEntry.PublicKey[:16]+"...", err)
		}
	}

	return tx.Commit()
}

func startCleaner(ctx context.Context) {
	if Retention <= 0 {
		return
	}

	logger.Printf("数据清理器已启动 (保留 %d 天)", Retention)
	defer logger.Println("数据清理器已停止")

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	cleanOldData()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanOldData()
		}
	}
}

func cleanOldData() {
	expireTime := time.Now().AddDate(0, 0, -Retention).Unix()
	result, err := db.Exec(`DELETE FROM traffic_history WHERE timestamp < ?`, expireTime)
	if err != nil {
		logger.Printf("清理旧数据失败: %v", err)
		return
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		logger.Printf("已清理 %d 条过期记录", affected)
	}
}

func startCacheCleaner(ctx context.Context) {
	logger.Println("缓存清理器已启动")
	defer logger.Println("缓存清理器已停止")

	ticker := time.NewTicker(CacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			latestPeersCache.Range(func(key, value interface{}) bool {
				entry := value.(cacheEntry)
				if now.Sub(entry.timestamp) > CacheTTL {
					latestPeersCache.Delete(key)
				}
				return true
			})
		}
	}
}

// ================= 辅助 API Handles & Queries =================

// 修改 main.go 中的 getRangeParams 函数
func getRangeParams(period string) (int64, int64) {
	now := time.Now().Unix()
	var duration, step int64

	switch period {
	case "realtime":
		duration = 1800 // 30 分钟窗口
		step = 10       // 优化点：从 2 改为 10，稀释数据密度
	case "1h":
		duration = 3600
		step = 30       // 优化点：每 30 秒一个点
	case "24h":
		duration = 86400
		step = 600      // 优化点：每 10 分钟一个点
	case "7d":
		duration = 604800
		step = 3600     // 优化点：每 1 小时一个点
	default:
		duration = 1800
		step = 10
	}
	return now - duration, step
}

func resampleData(rows *sql.Rows, step int64) ([]int64, []float64, []float64, error) {
	defer rows.Close()

	type bucket struct {
		rxSum float64
		txSum float64
		count int
	}
	buckets := make(map[int64]*bucket)

	for rows.Next() {
		var ts int64
		var rx, tx float64
		if err := rows.Scan(&ts, &rx, &tx); err != nil {
			logger.Printf("扫描行数据失败: %v", err)
			continue
		}

		slot := (ts / step) * step
		if _, ok := buckets[slot]; !ok {
			buckets[slot] = &bucket{}
		}
		buckets[slot].rxSum += rx
		buckets[slot].txSum += tx
		buckets[slot].count++
	}

	var timestamps []int64
	for ts := range buckets {
		timestamps = append(timestamps, ts)
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	var rxList, txList []float64
	for _, ts := range timestamps {
		b := buckets[ts]
		rxList = append(rxList, b.rxSum/float64(b.count))
		txList = append(txList, b.txSum/float64(b.count))
	}

	return timestamps, rxList, txList, nil
}

func validatePublicKey(pk string) error {
	if len(pk) == 0 { return errors.New("公钥不能为空") }
	if len(pk) > MaxPublicKeyLength { return errors.New("公钥长度超出限制") }
	if !publicKeyRegex.MatchString(pk) { return errors.New("公钥格式无效") }
	return nil
}

func validateAlias(alias string) error {
	if len(alias) == 0 { return errors.New("别名不能为空") }
	if len(alias) > MaxAliasLength { return errors.New("别名长度超出限制") }
	if strings.ContainsAny(alias, "<>\"';&|") { return errors.New("别名包含非法字符") }
	return nil
}

func getSystemStatus(c *gin.Context) {
	var sys SystemInfo

	if percent, err := cpu.Percent(0, false); err == nil && len(percent) > 0 {
		sys.CPUPercent = percent[0]
	}
	if v, err := mem.VirtualMemory(); err == nil {
		sys.MemPercent = v.UsedPercent
	}
	if h, err := host.Info(); err == nil {
		sys.Uptime = h.Uptime
		sys.HostName = h.Hostname
		sys.OS = h.Platform + " " + h.PlatformVersion
	}
	if temps, err := host.SensorsTemperatures(); err == nil {
		for _, t := range temps {
			sensorKey := strings.ToLower(t.SensorKey)
			if strings.Contains(sensorKey, "core") || strings.Contains(sensorKey, "input") {
				if t.Temperature > sys.CPUTemp {
					sys.CPUTemp = t.Temperature
				}
			}
		}
	}
	c.JSON(http.StatusOK, sys)
}

func getPeers(c *gin.Context) {
	client, err := wgctrl.New()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法连接 WireGuard"})
		return
	}
	defer client.Close()

	device, err := client.Device(WGInterface)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取设备信息"})
		return
	}

	aliasMap := make(map[string]string)
	rows, err := db.Query("SELECT public_key, alias FROM peer_aliases")
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var pk, a string
			rows.Scan(&pk, &a)
			aliasMap[pk] = a
		}
	}

	var peers []PeerData
	for _, p := range device.Peers {
		pk := p.PublicKey.String()
		
		var ips []string
		for _, ip := range p.AllowedIPs {
			ips = append(ips, ip.String())
		}

		ep := "未连接"
		if p.Endpoint != nil {
			ep = p.Endpoint.String()
		}

		var rxRate, txRate float64
		var isOnline bool

		if val, ok := latestPeersCache.Load(pk); ok {
			entry := val.(cacheEntry)
			rxRate = entry.data.RxRate
			txRate = entry.data.TxRate
			isOnline = entry.data.IsOnline
		} else {
			isOnline = !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < OnlineThreshold
		}

		peers = append(peers, PeerData{
			PublicKey:     pk,
			AllowedIPs:    ips,
			Endpoint:      ep,
			LastHandshake: p.LastHandshakeTime,
			ReceiveBytes:  p.ReceiveBytes,
			TransmitBytes: p.TransmitBytes,
			Alias:         aliasMap[pk],
			RxRate:        rxRate,
			TxRate:        txRate,
			IsOnline:      isOnline,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		if peers[i].IsOnline != peers[j].IsOnline {
			return peers[i].IsOnline
		}
		if len(peers[i].AllowedIPs) == 0 || len(peers[j].AllowedIPs) == 0 {
			return len(peers[i].AllowedIPs) > len(peers[j].AllowedIPs)
		}
		return peers[i].AllowedIPs[0] < peers[j].AllowedIPs[0]
	})

	c.JSON(http.StatusOK, gin.H{
		"interface": device.Name,
		"port":      device.ListenPort,
		"peers":     peers,
	})
}

func getPeerHistory(c *gin.Context) {
	pk := c.Param("publickey")
	if err := validatePublicKey(pk); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	period := c.DefaultQuery("period", "realtime")
	startTime, step := getRangeParams(period)

	query := `
		SELECT timestamp, rx_rate, tx_rate 
		FROM traffic_history 
		WHERE peer_public_key = ? AND timestamp >= ? 
		ORDER BY timestamp ASC
	`
	rows, err := db.Query(query, pk, startTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}

	ts, rx, tx, err := resampleData(rows, step)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据处理失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"labels": ts, "rates": gin.H{"rx": rx, "tx": tx}})
}

func getTrafficChartData(c *gin.Context) {
	period := c.DefaultQuery("period", "realtime")
	startTime, step := getRangeParams(period)

	query := `
		SELECT timestamp, SUM(rx_rate), SUM(tx_rate) 
		FROM traffic_history
		WHERE timestamp >= ?
		GROUP BY timestamp
		ORDER BY timestamp ASC
	`
	rows, err := db.Query(query, startTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}

	ts, rx, tx, err := resampleData(rows, step)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据处理失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"labels": ts, "rx": rx, "tx": tx})
}

func getStats(c *gin.Context) {
	startTime := time.Now().Unix() - 86400
	topQuery := `
		SELECT 
			t.peer_public_key,
			COALESCE(a.alias, '') as alias,
			MAX(t.rx_bytes) as total_rx,
			MAX(t.tx_bytes) as total_tx
		FROM traffic_history t
		LEFT JOIN peer_aliases a ON t.peer_public_key = a.public_key
		WHERE t.timestamp > ?
		GROUP BY t.peer_public_key
		ORDER BY total_rx DESC
		LIMIT 5
	`
	rows, err := db.Query(topQuery, startTime)
	if err != nil {
		logger.Printf("查询统计失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询统计失败"})
		return
	}
	defer rows.Close()

	var topPeers []gin.H
	for rows.Next() {
		var pk, alias string
		var rx, tx int64
		if err := rows.Scan(&pk, &alias, &rx, &tx); err == nil {
			topPeers = append(topPeers, gin.H{
				"public_key": pk,
				"alias":      alias,
				"total_rx":   rx,
				"total_tx":   tx,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"top_peers": topPeers})
}

func setAlias(c *gin.Context) {
	var req struct {
		PublicKey string `json:"public_key"`
		Alias     string `json:"alias"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}

	if err := validatePublicKey(req.PublicKey); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateAlias(req.Alias); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.Exec(`INSERT INTO peer_aliases (public_key, alias) VALUES (?, ?) ON CONFLICT(public_key) DO UPDATE SET alias = excluded.alias`, req.PublicKey, req.Alias)
	if err != nil {
		logger.Printf("设置别名失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
