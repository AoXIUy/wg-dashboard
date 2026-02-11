package main

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oschwald/geoip2-golang"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//go:embed index.html
var indexHtml string

// ================= 常量定义 =================
const (
	CollectInterval     = 2 * time.Second
	WriteInterval       = 6 * time.Second
	BatchSize           = 100
	MaxAliasLength      = 100
	MaxPublicKeyLength  = 200
	OnlineThreshold     = 3 * time.Minute
	DBMaxOpenConns      = 50
	DBMaxIdleConns      = 10
	DBConnMaxLifetime   = 10 * time.Minute
	DBConnMaxIdleTime   = 5 * time.Minute
	CacheTTL            = 5 * time.Minute
	ShutdownTimeout     = 30 * time.Second
	BitsPerByte         = 8.0
	MegabitsPerSecond   = 1000000.0
	TokenExpireDuration = 24 * time.Hour
	SSEBroadcastLimit   = 100 * time.Millisecond
	MaxRetries          = 3
	BufferMaxSize       = 1000
)

// ================= 配置区域 =================
var (
	WGInterface   string
	ServerPort    string
	MySQLDSN      string
	RedisAddr     string
	Retention     int
	AdminPassword string
	JWTSecret     string
	GeoCityPath   string
	GeoASNPath    string
)

// ================= 数据结构 =================

type RawSnapshot struct {
	Timestamp time.Time
	Peers     []wgtypes.Peer
}

type ProcessedLog struct {
	Timestamp int64
	PublicKey string
	Endpoint  string
	RxBytes   int64
	TxBytes   int64
	RxRate    float64
	TxRate    float64
	IsOnline  bool
	Latency   string
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
	Latency       string    `json:"latency"`
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

// --- 鉴权结构 ---
type LoginRequest struct {
	Password string `json:"password" binding:"required"`
}

type JwtClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

// --- 管理结构 ---
type AddPeerRequest struct {
	ConfigFile string `json:"config_file"`
	Name       string `json:"name"`
	AllowedIPs string `json:"allowed_ips"`
}

// --- 分析结构 ---
type PeerAnalysis struct {
	PublicKey    string  `json:"public_key"`
	Alias        string  `json:"alias"`
	TotalRx      int64   `json:"total_rx"`
	TotalTx      int64   `json:"total_tx"`
	Uptime       float64 `json:"uptime_percent"`
	HealthScore  int     `json:"health_score"`
	LastSeenTime int64   `json:"last_seen_time"`
}

type ActivityPoint struct {
	Hour  int     `json:"hour"`
	RxSum float64 `json:"rx_sum"`
	TxSum float64 `json:"tx_sum"`
}

type AnalysisReport struct {
	Peers         []PeerAnalysis  `json:"peers"`
	HourlyProfile []ActivityPoint `json:"hourly_profile"`
}

type AccessLog struct {
	Timestamp string `json:"timestamp"`
	Endpoint  string `json:"endpoint"`
	RxTotal   int64  `json:"rx_total"`
	TxTotal   int64  `json:"tx_total"`
}

// --- SSE 结构 (优化版) ---
type SSEBroker struct {
	Clients       map[chan string]bool
	NewClients    chan chan string
	ClosedClients chan chan string
	Message       chan string
	mu            sync.RWMutex
	rateLimit     time.Duration
	lastBroadcast atomic.Value // time.Time
}

type DashboardUpdate struct {
	Peers     []PeerData `json:"peers"`
	System    SystemInfo `json:"system"`
	Timestamp int64      `json:"timestamp"`
}

// ================= 优化: 别名缓存 =================
type AliasCache struct {
	mu         sync.RWMutex
	data       map[string]string
	lastUpdate time.Time
	ttl        time.Duration
}

func NewAliasCache(ttl time.Duration) *AliasCache {
	return &AliasCache{
		data: make(map[string]string),
		ttl:  ttl,
	}
}

func (ac *AliasCache) Get(pk string) (string, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	if time.Since(ac.lastUpdate) > ac.ttl {
		return "", false
	}

	alias, ok := ac.data[pk]
	return alias, ok
}

func (ac *AliasCache) Set(pk, alias string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.data[pk] = alias
}

func (ac *AliasCache) Refresh(ctx context.Context) error {
	rows, err := db.QueryContext(ctx, "SELECT public_key, alias FROM peer_aliases")
	if err != nil {
		return fmt.Errorf("query aliases: %w", err)
	}
	defer rows.Close()

	newData := make(map[string]string)
	for rows.Next() {
		var pk, alias string
		if err := rows.Scan(&pk, &alias); err != nil {
			logger.Printf("扫描别名失败: %v", err)
			continue
		}
		newData[pk] = alias
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	ac.mu.Lock()
	ac.data = newData
	ac.lastUpdate = time.Now()
	ac.mu.Unlock()

	logger.Printf("别名缓存已刷新，共 %d 条记录", len(newData))
	return nil
}

func (ac *AliasCache) NeedsRefresh() bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return time.Since(ac.lastUpdate) > ac.ttl
}

// ================= 优化: 内存缓冲队列 =================
type TrafficBuffer struct {
	mu      sync.Mutex
	entries []ProcessedLog
	maxSize int
}

func NewTrafficBuffer(maxSize int) *TrafficBuffer {
	return &TrafficBuffer{
		entries: make([]ProcessedLog, 0, maxSize),
		maxSize: maxSize,
	}
}

func (tb *TrafficBuffer) Add(entry ProcessedLog) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.entries = append(tb.entries, entry)
	return len(tb.entries) >= tb.maxSize
}

func (tb *TrafficBuffer) Flush() []ProcessedLog {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if len(tb.entries) == 0 {
		return nil
	}

	batch := make([]ProcessedLog, len(tb.entries))
	copy(batch, tb.entries)
	tb.entries = tb.entries[:0]
	return batch
}

func (tb *TrafficBuffer) Size() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return len(tb.entries)
}

// ================= 优化: 监控指标 =================
type Metrics struct {
	ProcessedCount int64
	FailedWrites   int64
	RedisErrors    int64
	CacheHits      int64
	CacheMisses    int64
}

func (m *Metrics) IncProcessed() {
	atomic.AddInt64(&m.ProcessedCount, 1)
}

func (m *Metrics) IncFailedWrites() {
	atomic.AddInt64(&m.FailedWrites, 1)
}

func (m *Metrics) IncRedisErrors() {
	atomic.AddInt64(&m.RedisErrors, 1)
}

func (m *Metrics) IncCacheHits() {
	atomic.AddInt64(&m.CacheHits, 1)
}

func (m *Metrics) IncCacheMisses() {
	atomic.AddInt64(&m.CacheMisses, 1)
}

func (m *Metrics) GetStats() map[string]int64 {
	return map[string]int64{
		"processed":     atomic.LoadInt64(&m.ProcessedCount),
		"failed_writes": atomic.LoadInt64(&m.FailedWrites),
		"redis_errors":  atomic.LoadInt64(&m.RedisErrors),
		"cache_hits":    atomic.LoadInt64(&m.CacheHits),
		"cache_misses":  atomic.LoadInt64(&m.CacheMisses),
	}
}

// ================= 优化: 延迟缓存 =================
type LatencyCache struct {
	mu   sync.RWMutex
	data map[string]string
}

func NewLatencyCache() *LatencyCache {
	return &LatencyCache{
		data: make(map[string]string),
	}
}

func (lc *LatencyCache) Get(pk string) string {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.data[pk]
}

func (lc *LatencyCache) Set(pk, latency string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.data[pk] = latency
}

func (lc *LatencyCache) Delete(pk string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	delete(lc.data, pk)
}

// ================= 全局变量 =================
var (
	db             *sql.DB
	rdb            *redis.Client
	configMu       sync.Mutex
	publicKeyRegex = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	logger         *log.Logger
	geoCity        *geoip2.Reader
	geoAsn         *geoip2.Reader
	sseBroker      *SSEBroker
	redisEnabled   bool
	aliasCache     *AliasCache
	trafficBuffer  *TrafficBuffer
	latencyCache   *LatencyCache
	metrics        *Metrics
)

// ================= 主程序 =================

func main() {
	logger = log.New(os.Stdout, "[WG-Monitor] ", log.LstdFlags|log.Lshortfile)

	flag.StringVar(&WGInterface, "iface", "wg0", "WireGuard 接口名称")
	flag.StringVar(&ServerPort, "port", ":8080", "Web 监听端口")
	flag.StringVar(&MySQLDSN, "mysql", "wg_user:cloud123@tcp(127.0.0.1:3306)/wg_monitor?charset=utf8mb4&parseTime=True&loc=Local", "MySQL 连接字符串")
	flag.StringVar(&RedisAddr, "redis", "192.168.10.119:6379", "Redis 地址")
	flag.IntVar(&Retention, "days", 30, "数据保留天数")
	flag.StringVar(&AdminPassword, "password", "admin123", "仪表盘访问密码")
	flag.StringVar(&JWTSecret, "secret", "change_this_secret_in_prod", "JWT 签名密钥")
	flag.StringVar(&GeoCityPath, "geo-city", "./GeoLite2-City.mmdb", "GeoLite2 City 数据库路径")
	flag.StringVar(&GeoASNPath, "geo-asn", "./GeoLite2-ASN.mmdb", "GeoLite2 ASN 数据库路径")
	flag.Parse()

	if v := os.Getenv("WG_ADMIN_PASSWORD"); v != "" {
		AdminPassword = v
	}
	if v := os.Getenv("WG_JWT_SECRET"); v != "" {
		JWTSecret = v
	}

	if os.Geteuid() != 0 {
		logger.Println("警告: 未以 Root 权限运行，无法管理 WireGuard 配置，仅能监控。")
	}

	// 初始化组件
	initGeoIP()
	initRedis()
	initComponents()

	if err := initDB(); err != nil {
		logger.Fatalf("数据库初始化失败: %v", err)
	}
	defer closeDB()

	// 初始化别名缓存
	if err := aliasCache.Refresh(context.Background()); err != nil {
		logger.Printf("初始别名缓存加载失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rawChan := make(chan RawSnapshot, 20)
	var wg sync.WaitGroup

	// 启动后台服务
	startBackgroundServices(ctx, &wg, rawChan)

	// 启动 HTTP 服务器
	srv := startHTTPServer()

	// 优雅关闭
	gracefulShutdown(srv, cancel, &wg)
}

func initGeoIP() {
	if _, err := os.Stat(GeoCityPath); err == nil {
		var err error
		geoCity, err = geoip2.Open(GeoCityPath)
		if err != nil {
			logger.Printf("GeoIP City 加载失败: %v", err)
		} else {
			logger.Println("GeoIP City 数据库已加载")
		}
	} else {
		logger.Printf("GeoIP City 数据库不存在: %s", GeoCityPath)
	}

	if _, err := os.Stat(GeoASNPath); err == nil {
		var err error
		geoAsn, err = geoip2.Open(GeoASNPath)
		if err != nil {
			logger.Printf("GeoIP ASN 加载失败: %v", err)
		} else {
			logger.Println("GeoIP ASN 数据库已加载")
		}
	} else {
		logger.Printf("GeoIP ASN 数据库不存在: %s", GeoASNPath)
	}
}

func initComponents() {
	aliasCache = NewAliasCache(CacheTTL)
	trafficBuffer = NewTrafficBuffer(BufferMaxSize)
	latencyCache = NewLatencyCache()
	metrics = &Metrics{}

	sseBroker = &SSEBroker{
		Clients:       make(map[chan string]bool),
		NewClients:    make(chan chan string),
		ClosedClients: make(chan chan string),
		Message:       make(chan string, 100),
		rateLimit:     SSEBroadcastLimit,
	}
	sseBroker.lastBroadcast.Store(time.Now())
}

func closeDB() {
	if db != nil {
		if err := db.Close(); err != nil {
			logger.Printf("数据库关闭失败: %v", err)
		}
	}
	if geoCity != nil {
		geoCity.Close()
	}
	if geoAsn != nil {
		geoAsn.Close()
	}
}

func startBackgroundServices(ctx context.Context, wg *sync.WaitGroup, rawChan chan RawSnapshot) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		startCollector(ctx, rawChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startProcessor(ctx, rawChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startAsyncWriter(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startCleaner(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startPinger(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		startSSEBroker()
	}()

	if redisEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startRedisBroadcastListener(ctx)
		}()
	}

	// 定期刷新别名缓存
	wg.Add(1)
	go func() {
		defer wg.Done()
		startCacheRefresher(ctx)
	}()
}

func startCacheRefresher(ctx context.Context) {
	ticker := time.NewTicker(CacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := aliasCache.Refresh(ctx); err != nil {
				logger.Printf("别名缓存刷新失败: %v", err)
			}
		}
	}
}

func gracefulShutdown(srv *http.Server, cancel context.CancelFunc, wg *sync.WaitGroup) {
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
	if token := c.Query("token"); token != "" {
		return token
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

// ================= SSE 优化逻辑 =================

func startSSEBroker() {
	for {
		select {
		case s := <-sseBroker.NewClients:
			sseBroker.mu.Lock()
			sseBroker.Clients[s] = true
			sseBroker.mu.Unlock()
			logger.Printf("新 SSE 客户端连接，当前连接数: %d", len(sseBroker.Clients))

		case s := <-sseBroker.ClosedClients:
			sseBroker.mu.Lock()
			delete(sseBroker.Clients, s)
			clientCount := len(sseBroker.Clients)
			sseBroker.mu.Unlock()
			close(s)
			logger.Printf("SSE 客户端断开，当前连接数: %d", clientCount)

		case msg := <-sseBroker.Message:
			sseBroker.mu.RLock()
			clientCount := len(sseBroker.Clients)
			sseBroker.mu.RUnlock()

			if clientCount == 0 {
				continue
			}

			// 限流检查
			lastBroadcast := sseBroker.lastBroadcast.Load().(time.Time)
			if time.Since(lastBroadcast) < sseBroker.rateLimit {
				continue
			}
			sseBroker.lastBroadcast.Store(time.Now())

			sseBroker.mu.RLock()
			for s := range sseBroker.Clients {
				select {
				case s <- msg:
				default:
					// 客户端阻塞，异步移除
					go func(client chan string) {
						sseBroker.mu.Lock()
						delete(sseBroker.Clients, client)
						sseBroker.mu.Unlock()
						close(client)
					}(s)
				}
			}
			sseBroker.mu.RUnlock()
		}
	}
}

func startRedisBroadcastListener(ctx context.Context) {
	logger.Println("Redis Pub/Sub 监听器已启动")
	defer logger.Println("Redis Pub/Sub 监听器已停止")

	pubsub := rdb.Subscribe(ctx, "wg:channel:broadcast")
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			select {
			case sseBroker.Message <- msg.Payload:
			default:
			}
		}
	}
}

func streamHandler(c *gin.Context) {
	clientChan := make(chan string, 10) // 增加缓冲
	sseBroker.NewClients <- clientChan

	defer func() {
		sseBroker.ClosedClients <- clientChan
	}()

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // 禁用 Nginx 缓冲

	c.Stream(func(w io.Writer) bool {
		select {
		case msg, ok := <-clientChan:
			if !ok {
				return false
			}
			c.SSEvent("message", msg)
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}

// ================= GeoIP 逻辑 =================

func getGeoIPInfo(c *gin.Context) {
	ipStr := c.Query("ip")
	if ipStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing ip"})
		return
	}

	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ipStr = strings.Trim(ipStr, "[]")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ip"})
		return
	}

	resp := gin.H{}

	if geoCity != nil {
		if record, err := geoCity.City(ip); err == nil {
			resp["country_code"] = record.Country.IsoCode
			if name, ok := record.City.Names["zh-CN"]; ok && name != "" {
				resp["city"] = name
			} else {
				resp["city"] = record.City.Names["en"]
			}
			resp["latitude"] = record.Location.Latitude
			resp["longitude"] = record.Location.Longitude
		}
	}

	if geoAsn != nil {
		if record, err := geoAsn.ASN(ip); err == nil {
			resp["asn"] = record.AutonomousSystemOrganization
			resp["asn_number"] = record.AutonomousSystemNumber
		}
	}

	c.JSON(http.StatusOK, resp)
}

func isValidConfigName(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return validName.MatchString(name)
}

// ================= 数据库逻辑 (优化版) =================

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

	// 创建表
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

	logger.Println("数据库初始化成功")
	return nil
}

// ================= 数据收集共享逻辑 (优化版) =================

func collectSystemInfo() SystemInfo {
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
			if t.Temperature > sys.CPUTemp {
				sys.CPUTemp = t.Temperature
			}
		}
	}

	return sys
}

func collectPeersData() ([]PeerData, string, int, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, "", 0, fmt.Errorf("创建 WireGuard 客户端失败: %w", err)
	}
	defer client.Close()

	device, err := client.Device(WGInterface)
	if err != nil {
		return nil, "", 0, fmt.Errorf("获取设备信息失败: %w", err)
	}

	// 刷新别名缓存（如果需要）
	if aliasCache.NeedsRefresh() {
		go aliasCache.Refresh(context.Background())
	}

	// 批量获取 Redis 状态
	var redisCmds map[string]*redis.StringStringMapCmd
	if redisEnabled {
		pipe := rdb.Pipeline()
		redisCmds = make(map[string]*redis.StringStringMapCmd)
		for _, p := range device.Peers {
			key := fmt.Sprintf("wg:peer:state:%s", p.PublicKey.String())
			redisCmds[p.PublicKey.String()] = pipe.HGetAll(context.Background(), key)
		}
		if _, err := pipe.Exec(context.Background()); err != nil {
			logger.Printf("Redis Pipeline 执行失败: %v", err)
			metrics.IncRedisErrors()
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

		// 从 Redis 获取实时状态
		if redisEnabled && redisCmds != nil {
			if val, err := redisCmds[pk].Result(); err == nil && len(val) > 0 {
				rxRate, _ = strconv.ParseFloat(val["rx_rate"], 64)
				txRate, _ = strconv.ParseFloat(val["tx_rate"], 64)
				onlineInt, _ := strconv.Atoi(val["is_online"])
				isOnline = onlineInt == 1
			}
		}

		// 回退到握手时间判断
		if !isOnline && !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < OnlineThreshold {
			isOnline = true
		}

		// 从缓存获取别名
		alias, _ := aliasCache.Get(pk)

		peers = append(peers, PeerData{
			PublicKey:     pk,
			AllowedIPs:    ips,
			Endpoint:      ep,
			LastHandshake: p.LastHandshakeTime,
			ReceiveBytes:  p.ReceiveBytes,
			TransmitBytes: p.TransmitBytes,
			Alias:         alias,
			RxRate:        rxRate,
			TxRate:        txRate,
			IsOnline:      isOnline,
			Latency:       latencyCache.Get(pk),
		})
	}

	// 排序
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].IsOnline != peers[j].IsOnline {
			return peers[i].IsOnline
		}
		rateI := peers[i].RxRate + peers[i].TxRate
		rateJ := peers[j].RxRate + peers[j].TxRate
		if rateI != rateJ {
			return rateI > rateJ
		}
		return peers[i].LastHandshake.After(peers[j].LastHandshake)
	})

	return peers, device.PublicKey.String(), device.ListenPort, nil
}

// ================= Ping 监控逻辑 =================

func startPinger(ctx context.Context) {
	logger.Println("Ping 监控已启动")
	defer logger.Println("Ping 监控已停止")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if db == nil {
				continue
			}

			peers, _, _, err := collectPeersData()
			if err != nil {
				logger.Printf("获取 Peer 列表失败: %v", err)
				continue
			}

			var wg sync.WaitGroup
			semaphore := make(chan struct{}, 10) // 限制并发数

			for _, p := range peers {
				if !p.IsOnline || len(p.AllowedIPs) == 0 {
					latencyCache.Delete(p.PublicKey)
					continue
				}

				targetIP := strings.Split(p.AllowedIPs[0], "/")[0]
				if strings.Contains(targetIP, ":") {
					continue
				}

				wg.Add(1)
				go func(pk, ip string) {
					defer wg.Done()

					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					latency := pingHost(ip)
					if latency > 0 {
						latencyCache.Set(pk, fmt.Sprintf("%dms", latency))
					} else {
						latencyCache.Delete(pk)
					}
				}(p.PublicKey, targetIP)
			}

			wg.Wait()
		}
	}
}

func pingHost(ip string) int64 {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return 0
	}
	duration := time.Since(start)
	return duration.Milliseconds()
}

// ================= Pipeline 监控核心 (优化版) =================

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
		return nil
	}

	if err := reconnect(); err != nil {
		logger.Printf("初始连接失败，将在后续重试")
	}
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
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
				logger.Printf("获取设备信息失败: %v，尝试重连", err)
				reconnect()
				continue
			}

			select {
			case out <- RawSnapshot{Timestamp: time.Now(), Peers: device.Peers}:
			case <-ctx.Done():
				return
			default:
				logger.Println("警告: 采集通道已满，跳过此快照")
			}
		}
	}
}

func startProcessor(ctx context.Context, in <-chan RawSnapshot) {
	logger.Println("处理器已启动")
	defer logger.Println("处理器已停止")

	stateMap := make(map[string]*PeerState)

	for {
		select {
		case <-ctx.Done():
			return
		case snap, ok := <-in:
			if !ok {
				return
			}

			processSnapshot(ctx, snap, stateMap)
		}
	}
}

func processSnapshot(ctx context.Context, snap RawSnapshot, stateMap map[string]*PeerState) {
	var pipe redis.Pipeliner
	if redisEnabled {
		pipe = rdb.Pipeline()
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

		epStr := ""
		if p.Endpoint != nil {
			epStr = p.Endpoint.IP.String()
		}

		logEntry := ProcessedLog{
			Timestamp: snap.Timestamp.Unix(),
			PublicKey: pk,
			Endpoint:  epStr,
			RxBytes:   p.ReceiveBytes,
			TxBytes:   p.TransmitBytes,
			RxRate:    rxRate,
			TxRate:    txRate,
			IsOnline:  isOnline,
		}

		// 写入内存缓冲
		shouldFlush := trafficBuffer.Add(logEntry)
		metrics.IncProcessed()

		// 立即刷新
		if shouldFlush {
			go func() {
				batch := trafficBuffer.Flush()
				if batch != nil {
					flushMySQL(batch)
				}
			}()
		}

		// 更新 Redis (异步)
		if redisEnabled && pipe != nil {
			updateRedisState(pipe, ctx, pk, rxRate, txRate, isOnline, epStr, snap.Timestamp.Unix())
		}
	}

	// 执行 Redis Pipeline
	if redisEnabled && pipe != nil {
		if _, err := pipe.Exec(ctx); err != nil {
			logger.Printf("Redis Pipeline 执行失败: %v", err)
			metrics.IncRedisErrors()
		} else {
			// 广播更新
			broadcastUpdate(ctx)
		}
	}
}

func updateRedisState(pipe redis.Pipeliner, ctx context.Context, pk string, rxRate, txRate float64, isOnline bool, endpoint string, timestamp int64) {
	key := fmt.Sprintf("wg:peer:state:%s", pk)
	onlineVal := 0
	if isOnline {
		onlineVal = 1
	}

	pipe.HSet(ctx, key, map[string]interface{}{
		"rx_rate":   rxRate,
		"tx_rate":   txRate,
		"is_online": onlineVal,
		"endpoint":  endpoint,
		"last_seen": timestamp,
	})
	pipe.Expire(ctx, key, 5*time.Minute)
}

func broadcastUpdate(ctx context.Context) {
	peers, _, _, err := collectPeersData()
	if err != nil {
		logger.Printf("收集 Peer 数据失败: %v", err)
		return
	}

	update := DashboardUpdate{
		Peers:     peers,
		System:    collectSystemInfo(),
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(update)
	if err != nil {
		logger.Printf("序列化更新数据失败: %v", err)
		return
	}

	if redisEnabled {
		// 通过 Redis Pub/Sub 广播
		if err := rdb.Publish(ctx, "wg:channel:broadcast", string(jsonData)).Err(); err != nil {
			logger.Printf("Redis 发布失败: %v", err)
			metrics.IncRedisErrors()
		}
	} else {
		// 直接推送到 SSE
		select {
		case sseBroker.Message <- string(jsonData):
		default:
		}
	}
}

// ================= 异步写入逻辑 (优化版) =================

func startAsyncWriter(ctx context.Context) {
	logger.Println("异步写入器已启动")
	defer logger.Println("异步写入器已停止")

	ticker := time.NewTicker(WriteInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 最后刷新
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

	// 最终失败，记录到文件
	backupToFile(batch)
}

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

	failed := 0
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
			failed++
			logger.Printf("插入记录失败 [%s]: %v", logEntry.PublicKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	if failed > 0 {
		logger.Printf("批量插入完成，成功 %d/%d 条", len(batch)-failed, len(batch))
	}

	return nil
}

func backupToFile(batch []ProcessedLog) {
	backupDir := "/var/log/wg-monitor"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		logger.Printf("创建备份目录失败: %v", err)
		return
	}

	filename := fmt.Sprintf("backup_%d.json", time.Now().Unix())
	filepath := filepath.Join(backupDir, filename)

	f, err := os.Create(filepath)
	if err != nil {
		logger.Printf("创建备份文件失败: %v", err)
		return
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(batch); err != nil {
		logger.Printf("写入备份文件失败: %v", err)
		return
	}

	logger.Printf("已备份 %d 条记录到 %s", len(batch), filepath)
}

// ================= 数据清理逻辑 =================

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

// ================= HTTP 服务器配置 =================

func startHTTPServer() *http.Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, indexHtml)
	})

	r.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./static/favicon.ico")
	})

	setupAPIRoutes(r)

	srv := &http.Server{
		Addr:         ServerPort,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Printf("==============================================")
		logger.Printf("WireGuard Monitor & Manager 启动成功")
		logger.Printf("接口: %s | 端口: %s", WGInterface, ServerPort)
		logger.Printf("数据库: MySQL | Redis: %v", redisEnabled)
		logger.Printf("==============================================")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("HTTP 服务器启动失败: %v", err)
		}
	}()

	return srv
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func setupAPIRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		api.POST("/login", loginHandler)
		api.GET("/check_auth", checkAuthHandler)
		api.GET("/metrics", metricsHandler)

		authorized := api.Group("/")
		authorized.Use(authMiddleware())
		{
			authorized.GET("/stream", streamHandler)
			authorized.GET("/peers", getPeers)
			authorized.GET("/history/:publickey", getPeerHistory)
			authorized.GET("/history/logs/:publickey", getPeerAccessLogs)
			authorized.GET("/chart/traffic", getTrafficChartData)
			authorized.GET("/system", getSystemStatus)
			authorized.POST("/alias", setAlias)
			authorized.GET("/geoip", getGeoIPInfo)
			authorized.GET("/analysis", getAnalysisHandler)

			manage := authorized.Group("/manage")
			{
				manage.GET("/configs", listConfigFiles)
				manage.POST("/peer", addPeer)
				manage.DELETE("/peer", removePeer)
				manage.GET("/suggest_ip", suggestIPHandler)
			}
		}
	}
}

func checkAuthHandler(c *gin.Context) {
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
}

func metricsHandler(c *gin.Context) {
	stats := metrics.GetStats()

	output := fmt.Sprintf(`# HELP wg_processed_total Total processed snapshots
# TYPE wg_processed_total counter
wg_processed_total %d

# HELP wg_failed_writes_total Failed MySQL writes
# TYPE wg_failed_writes_total counter
wg_failed_writes_total %d

# HELP wg_redis_errors_total Redis operation errors
# TYPE wg_redis_errors_total counter
wg_redis_errors_total %d

# HELP wg_cache_hits_total Cache hits
# TYPE wg_cache_hits_total counter
wg_cache_hits_total %d

# HELP wg_cache_misses_total Cache misses
# TYPE wg_cache_misses_total counter
wg_cache_misses_total %d

# HELP wg_buffer_size Current buffer size
# TYPE wg_buffer_size gauge
wg_buffer_size %d
`,
		stats["processed"],
		stats["failed_writes"],
		stats["redis_errors"],
		stats["cache_hits"],
		stats["cache_misses"],
		trafficBuffer.Size(),
	)

	c.String(http.StatusOK, output)
}

// ================= 数据 API =================

func getRangeParams(period string) (int64, int64) {
	now := time.Now().Unix()
	var duration, step int64
	switch period {
	case "realtime":
		duration, step = 1800, 10
	case "1h":
		duration, step = 3600, 30
	case "24h":
		duration, step = 86400, 600
	case "7d":
		duration, step = 604800, 3600
	default:
		duration, step = 1800, 10
	}
	return now - duration, step
}

func getSystemStatus(c *gin.Context) {
	sys := collectSystemInfo()
	c.JSON(http.StatusOK, sys)
}

func getPeers(c *gin.Context) {
	peers, name, port, err := collectPeersData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取设备信息: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"interface": name,
		"port":      port,
		"peers":     peers,
	})
}

func getPeerHistory(c *gin.Context) {
	pk := c.Param("publickey")
	period := c.DefaultQuery("period", "realtime")
	startTime, step := getRangeParams(period)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT timestamp, rx_rate, tx_rate 
		FROM traffic_history 
		WHERE peer_public_key = ? AND timestamp >= ? 
		ORDER BY timestamp ASC
	`, pk, startTime)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败: " + err.Error()})
		return
	}
	defer rows.Close()

	type bucket struct {
		rx, tx float64
		count  int
	}
	buckets := make(map[int64]*bucket)

	for rows.Next() {
		var ts int64
		var rx, tx float64
		if err := rows.Scan(&ts, &rx, &tx); err != nil {
			continue
		}
		slot := (ts / step) * step
		if _, ok := buckets[slot]; !ok {
			buckets[slot] = &bucket{}
		}
		buckets[slot].rx += rx
		buckets[slot].tx += tx
		buckets[slot].count++
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据读取错误: " + err.Error()})
		return
	}

	tsList := make([]int64, 0, len(buckets))
	for t := range buckets {
		tsList = append(tsList, t)
	}
	sort.Slice(tsList, func(i, j int) bool { return tsList[i] < tsList[j] })

	var rxList, txList []float64
	for _, t := range tsList {
		b := buckets[t]
		rxList = append(rxList, b.rx/float64(b.count))
		txList = append(txList, b.tx/float64(b.count))
	}

	c.JSON(http.StatusOK, gin.H{
		"labels":  tsList,
		"rates":   gin.H{"rx": rxList, "tx": txList},
		"latency": latencyCache.Get(pk),
	})
}

func getPeerAccessLogs(c *gin.Context) {
	pk := c.Param("publickey")
	since := time.Now().AddDate(0, 0, -30).Unix()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	query := `
		SELECT timestamp, endpoint, rx_bytes, tx_bytes
		FROM traffic_history 
		WHERE peer_public_key = ? 
		  AND endpoint != '' 
		  AND timestamp > ?
		ORDER BY timestamp ASC
	`

	rows, err := db.QueryContext(ctx, query, pk, since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询记录失败: " + err.Error()})
		return
	}
	defer rows.Close()

	type epStat struct {
		lastSeen int64
		rx       int64
		tx       int64
	}
	stats := make(map[string]*epStat)

	var prevRx, prevTx int64 = -1, -1

	for rows.Next() {
		var ts int64
		var ep string
		var rx, tx int64
		if err := rows.Scan(&ts, &ep, &rx, &tx); err != nil {
			continue
		}

		if prevRx == -1 {
			prevRx = rx
			prevTx = tx
			if _, ok := stats[ep]; !ok {
				stats[ep] = &epStat{lastSeen: ts, rx: 0, tx: 0}
			}
			continue
		}

		deltaRx := rx - prevRx
		deltaTx := tx - prevTx

		if deltaRx < 0 {
			deltaRx = rx
		}
		if deltaTx < 0 {
			deltaTx = tx
		}

		if _, ok := stats[ep]; !ok {
			stats[ep] = &epStat{}
		}
		stats[ep].lastSeen = ts
		stats[ep].rx += deltaRx
		stats[ep].tx += deltaTx

		prevRx = rx
		prevTx = tx
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据读取错误: " + err.Error()})
		return
	}

	var logs []AccessLog
	for ep, s := range stats {
		tStr := time.Unix(s.lastSeen, 0).Format("2006-01-02 15:04")
		logs = append(logs, AccessLog{
			Timestamp: tStr,
			Endpoint:  ep,
			RxTotal:   s.rx,
			TxTotal:   s.tx,
		})
	}

	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp > logs[j].Timestamp
	})

	if len(logs) > 100 {
		logs = logs[:100]
	}

	if logs == nil {
		logs = []AccessLog{}
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

func getTrafficChartData(c *gin.Context) {
	period := c.DefaultQuery("period", "realtime")
	startTime, step := getRangeParams(period)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT timestamp, SUM(rx_rate), SUM(tx_rate) 
		FROM traffic_history 
		WHERE timestamp >= ? 
		GROUP BY timestamp 
		ORDER BY timestamp ASC
	`, startTime)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败: " + err.Error()})
		return
	}
	defer rows.Close()

	buckets := make(map[int64]struct{ rx, tx float64; count int })

	for rows.Next() {
		var ts int64
		var rx, tx float64
		if err := rows.Scan(&ts, &rx, &tx); err != nil {
			continue
		}
		slot := (ts / step) * step
		b := buckets[slot]
		b.rx += rx
		b.tx += tx
		b.count++
		buckets[slot] = b
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据读取错误: " + err.Error()})
		return
	}

	tsList := make([]int64, 0, len(buckets))
	for t := range buckets {
		tsList = append(tsList, t)
	}
	sort.Slice(tsList, func(i, j int) bool { return tsList[i] < tsList[j] })

	var rxList, txList []float64
	for _, t := range tsList {
		b := buckets[t]
		div := float64(1)
		if b.count > 0 {
			div = float64(b.count)
		}
		rxList = append(rxList, b.rx/div)
		txList = append(txList, b.tx/div)
	}

	c.JSON(http.StatusOK, gin.H{"labels": tsList, "rx": rxList, "tx": txList})
}

func setAlias(c *gin.Context) {
	var req struct {
		PublicKey string `json:"public_key"`
		Alias     string `json:"alias"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, `
		INSERT INTO peer_aliases (public_key, alias) 
		VALUES (?, ?) 
		ON DUPLICATE KEY UPDATE alias = VALUES(alias)
	`, req.PublicKey, req.Alias)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新别名失败: " + err.Error()})
		return
	}

	// 更新缓存
	aliasCache.Set(req.PublicKey, req.Alias)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func getAnalysisHandler(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		days = 7
	}

	report, err := getAnalysisReport(c, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

// ================= 深度分析逻辑 =================

func generateAnalysisReport(ctx context.Context, days int) (*AnalysisReport, error) {
	startTime := time.Now().AddDate(0, 0, -days).Unix()
	report := &AnalysisReport{}

	// 使用缓存的别名
	if aliasCache.NeedsRefresh() {
		aliasCache.Refresh(ctx)
	}

	q := `
		SELECT peer_public_key, COUNT(*), SUM(is_online), SUM(rx_rate), SUM(tx_rate), MAX(timestamp) 
		FROM traffic_history 
		WHERE timestamp > ? 
		GROUP BY peer_public_key
	`

	pRows, err := db.QueryContext(ctx, q, startTime)
	if err != nil {
		return nil, fmt.Errorf("查询 Peer 分析数据失败: %w", err)
	}
	defer pRows.Close()

	for pRows.Next() {
		var pk string
		var count int64
		var onlineSum, rxSum, txSum float64
		var lastSeen int64

		if err := pRows.Scan(&pk, &count, &onlineSum, &rxSum, &txSum, &lastSeen); err != nil {
			continue
		}

		if count == 0 {
			count = 1
		}

		estRx := int64(rxSum * 6.0 * 1000000 / 8)
		estTx := int64(txSum * 6.0 * 1000000 / 8)

		uptime := (onlineSum / float64(count)) * 100
		score := int(uptime)
		if lastSeen < time.Now().Add(-24*time.Hour).Unix() {
			score -= 30
		}
		if score < 0 {
			score = 0
		}

		alias, _ := aliasCache.Get(pk)

		report.Peers = append(report.Peers, PeerAnalysis{
			PublicKey:    pk,
			Alias:        alias,
			TotalRx:      estRx,
			TotalTx:      estTx,
			Uptime:       uptime,
			HealthScore:  score,
			LastSeenTime: lastSeen,
		})
	}

	if err := pRows.Err(); err != nil {
		return nil, fmt.Errorf("Peer 数据读取错误: %w", err)
	}

	sort.Slice(report.Peers, func(i, j int) bool {
		return (report.Peers[i].TotalRx + report.Peers[i].TotalTx) > (report.Peers[j].TotalRx + report.Peers[j].TotalTx)
	})

	// 小时分析
	hQuery := `
		SELECT timestamp, SUM(rx_rate + tx_rate) 
		FROM traffic_history 
		WHERE timestamp > ? 
		GROUP BY timestamp
	`

	hRows, err := db.QueryContext(ctx, hQuery, startTime)
	if err == nil {
		defer hRows.Close()

		hourMap := make(map[int]float64)
		hourCount := make(map[int]int)

		for hRows.Next() {
			var ts int64
			var rate float64
			if err := hRows.Scan(&ts, &rate); err != nil {
				continue
			}
			h := time.Unix(ts, 0).Hour()
			hourMap[h] += rate
			hourCount[h]++
		}

		for i := 0; i < 24; i++ {
			avg := 0.0
			if c := hourCount[i]; c > 0 {
				avg = hourMap[i] / float64(c)
			}
			report.HourlyProfile = append(report.HourlyProfile, ActivityPoint{Hour: i, RxSum: avg, TxSum: 0})
		}
	}

	return report, nil
}

func getAnalysisReport(c *gin.Context, days int) (*AnalysisReport, error) {
	if !redisEnabled {
		report, err := generateAnalysisReport(c.Request.Context(), days)
		if err == nil {
			c.Header("X-Cache", "DISABLED")
		}
		return report, err
	}

	cacheKey := fmt.Sprintf("wg:cache:analysis:%d", days)

	// 尝试从 Redis 获取
	val, err := rdb.Get(c.Request.Context(), cacheKey).Result()
	if err == nil {
		var report AnalysisReport
		if err := json.Unmarshal([]byte(val), &report); err == nil {
			c.Header("X-Cache", "HIT")
			metrics.IncCacheHits()
			return &report, nil
		}
	}

	metrics.IncCacheMisses()

	// 缓存未命中，查询 MySQL
	report, err := generateAnalysisReport(c.Request.Context(), days)
	if err == nil {
		jsonBytes, _ := json.Marshal(report)
		rdb.Set(c.Request.Context(), cacheKey, jsonBytes, 1*time.Minute)
		c.Header("X-Cache", "MISS")
	}

	return report, err
}

// ================= 管理功能逻辑 =================

func listConfigFiles(c *gin.Context) {
	files, err := filepath.Glob("/etc/wireguard/*.conf")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法扫描配置目录"})
		return
	}

	var configs []string
	for _, f := range files {
		base := filepath.Base(f)
		configs = append(configs, base[:len(base)-len(filepath.Ext(base))])
	}

	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

func addPeer(c *gin.Context) {
	configMu.Lock()
	defer configMu.Unlock()

	var req AddPeerRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if _, _, err := net.ParseCIDR(req.AllowedIPs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP格式错误，应为CIDR格式 (如 10.0.0.5/32)"})
		return
	}

	if req.ConfigFile == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "配置名不能为空"})
		return
	}

	if !isValidConfigName(req.ConfigFile) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法配置名，仅允许字母数字下划线"})
		return
	}

	client, err := wgctrl.New()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法连接 WG 控制器"})
		return
	}
	defer client.Close()

	device, err := client.Device(req.ConfigFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取接口信息: " + req.ConfigFile})
		return
	}

	pKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成私钥失败"})
		return
	}
	pubKey := pKey.PublicKey()

	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成预共享密钥失败"})
		return
	}

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", req.ConfigFile)
	f, err := os.OpenFile(confPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开配置文件(Permission?)"})
		return
	}
	defer f.Close()

	peerBlock := fmt.Sprintf("\n# Name: %s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n",
		req.Name, pubKey.String(), presharedKey.String(), req.AllowedIPs)

	if _, err := f.WriteString(peerBlock); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置失败"})
		return
	}

	// 更新数据库和缓存
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	db.ExecContext(ctx, `
		INSERT INTO peer_aliases (public_key, alias) 
		VALUES (?, ?) 
		ON DUPLICATE KEY UPDATE alias = VALUES(alias)
	`, pubKey.String(), req.Name)

	aliasCache.Set(pubKey.String(), req.Name)

	if err := reloadWireGuard(req.ConfigFile); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "saved_but_reload_failed",
			"error":  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":            "ok",
		"private_key":       pKey.String(),
		"public_key":        pubKey.String(),
		"preshared_key":     presharedKey.String(),
		"server_public_key": device.PublicKey.String(),
		"server_port":       device.ListenPort,
	})
}

func removePeer(c *gin.Context) {
	configFile := c.Query("config")
	pubKey := c.Query("public_key")

	configMu.Lock()
	defer configMu.Unlock()

	if configFile == "" || pubKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数缺失"})
		return
	}

	if !isValidConfigName(configFile) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法配置名"})
		return
	}

	if err := modifyConfigFile(configFile, pubKey, "remove"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改文件失败: " + err.Error()})
		return
	}

	if err := reloadWireGuard(configFile); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重载失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func reloadWireGuard(confName string) error {
	wgQuickPath := "/usr/bin/wg-quick"
	wgPath := "/usr/bin/wg"

	if _, err := os.Stat(wgQuickPath); os.IsNotExist(err) {
		wgQuickPath = "wg-quick"
	}
	if _, err := os.Stat(wgPath); os.IsNotExist(err) {
		wgPath = "wg"
	}

	cmdStrip := exec.Command(wgQuickPath, "strip", "/etc/wireguard/"+confName+".conf")
	configData, err := cmdStrip.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("strip failed: %v, stderr: %s", err, string(exitErr.Stderr))
		}
		return fmt.Errorf("strip failed: %v", err)
	}

	cmdSync := exec.Command(wgPath, "syncconf", confName, "/dev/stdin")
	cmdSync.Stdin = bytes.NewReader(configData)

	if output, err := cmdSync.CombinedOutput(); err != nil {
		return fmt.Errorf("syncconf failed: %v, output: %s", err, string(output))
	}

	logger.Printf("WireGuard (%s) 热重载成功", confName)
	return nil
}

func suggestIPHandler(c *gin.Context) {
	configMu.Lock()
	defer configMu.Unlock()

	confName := c.Query("config")
	if confName == "" {
		confName = "wg0"
	}

	if !isValidConfigName(confName) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法配置名"})
		return
	}

	path := fmt.Sprintf("/etc/wireguard/%s.conf", confName)
	content, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取配置文件"})
		return
	}

	serverIPStr := ""
	lines := strings.Split(string(content), "\n")
	reAddr := regexp.MustCompile(`(?i)^\s*Address\s*=\s*([0-9.]+)(/[0-9]+)?`)

	usedIPs := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := reAddr.FindStringSubmatch(line); len(matches) > 1 {
			if serverIPStr == "" && strings.Contains(matches[1], ".") {
				serverIPStr = matches[1]
				usedIPs[matches[1]] = true
			}
		}

		if strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "allowedips") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				ips := strings.Split(parts[1], ",")
				for _, ipCidr := range ips {
					if ip, _, err := net.ParseCIDR(strings.TrimSpace(ipCidr)); err == nil {
						usedIPs[ip.String()] = true
					}
				}
			}
		}
	}

	if serverIPStr == "" {
		serverIPStr = "10.0.0.1"
	}

	ip := net.ParseIP(serverIPStr)
	if ip == nil {
		ip = net.ParseIP("10.0.0.1")
	}
	ip = ip.To4()

	baseIP := ip.Mask(net.CIDRMask(24, 32))
	suggested := ""
	for i := 2; i < 255; i++ {
		candidate := net.IPv4(baseIP[0], baseIP[1], baseIP[2], byte(i))
		candidateStr := candidate.String()
		if !usedIPs[candidateStr] {
			suggested = candidateStr + "/32"
			break
		}
	}

	if suggested == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "该网段 IP 已耗尽"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ip": suggested})
}

func modifyConfigFile(confName, targetPubKey, action string) error {
	path := "/etc/wireguard/" + confName + ".conf"
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inTargetPeer := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimLine := strings.TrimSpace(line)

		if trimLine == "[Peer]" {
			isTarget := false
			for j := i + 1; j < len(lines) && j < i+15; j++ {
				if strings.Contains(lines[j], targetPubKey) {
					isTarget = true
					break
				}
				if strings.TrimSpace(lines[j]) == "[Peer]" || strings.TrimSpace(lines[j]) == "[Interface]" {
					break
				}
			}

			if isTarget {
				if action == "remove" {
					inTargetPeer = true
					if len(newLines) > 0 && strings.HasPrefix(strings.TrimSpace(newLines[len(newLines)-1]), "# Name:") {
						newLines = newLines[:len(newLines)-1]
					}
					continue
				}
			}
		}

		if inTargetPeer {
			if (trimLine == "" || strings.HasPrefix(trimLine, "[")) && trimLine != "[Peer]" && !strings.Contains(trimLine, targetPubKey) {
				inTargetPeer = false
				if trimLine != "" {
					newLines = append(newLines, line)
				}
			}
			continue
		}

		newLines = append(newLines, line)
	}

	output := strings.Join(newLines, "\n")
	return os.WriteFile(path, []byte(output), 0600)
}

func initRedis() {
	rdb = redis.NewClient(&redis.Options{
		Addr:         RedisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Printf("Redis 连接失败: %v (将禁用缓存/队列功能)", err)
		redisEnabled = false
	} else {
		logger.Println("Redis 已连接")
		redisEnabled = true
	}
}