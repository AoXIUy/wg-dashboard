package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/natefinch/lumberjack.v2"

	"wg-dashboard/pkg/ipapi"
)

// ================= 日志系统 =================

// initLogger 初始化日志系统，同时输出到文件（轮转）和控制台
func initLogger() {
	logFile := &lumberjack.Logger{
		Filename:   "./app.log",
		MaxSize:    100,  // 单文件最大 100MB
		MaxBackups: 7,    // 保留 7 个备份
		MaxAge:     30,   // 保留 30 天
		Compress:   true, // 压缩旧日志
		LocalTime:  true, // 使用本地时间
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(multiWriter, "[WG-Monitor] ", log.LstdFlags|log.Lshortfile)

	logger.Println("日志系统初始化完成，日志将输出到 app.log")
}

// ================= 初始化辅助 =================

// initGeoIP 根据命令行参数加载 GeoLite2 数据库；任一文件存在即初始化
func initGeoIP() {
	cityExists := false
	asnExists := false

	if _, err := os.Stat(GeoCityPath); err == nil {
		cityExists = true
	} else {
		logger.Printf("GeoIP City 数据库不存在: %s", GeoCityPath)
	}

	if _, err := os.Stat(GeoASNPath); err == nil {
		asnExists = true
	} else {
		logger.Printf("GeoIP ASN 数据库不存在: %s", GeoASNPath)
	}

	if cityExists || asnExists {
		cityPath := ""
		asnPath := ""
		if cityExists {
			cityPath = GeoCityPath
		}
		if asnExists {
			asnPath = GeoASNPath
		}

		provider, err := ipapi.NewGeoLite2Provider(cityPath, asnPath, true) // 启用外部 API 回退
		if err != nil {
			logger.Printf("GeoIP 初始化失败: %v", err)
		} else {
			ipProvider = provider
			logger.Println("GeoIP 数据库已加载")
		}
	}
}

// initRedis 连接 Redis，失败时将 redisEnabled 设为 false
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

// initComponents 初始化所有内存组件（缓存、SSE Broker 等）
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

// ================= 后台服务编排 =================

// startBackgroundServices 启动所有后台 goroutine
func startBackgroundServices(ctx context.Context, wg *sync.WaitGroup, rawChan chan RawSnapshot) {
	wg.Add(1)
	go func() { defer wg.Done(); startCollector(ctx, rawChan) }()

	wg.Add(1)
	go func() { defer wg.Done(); startProcessor(ctx, rawChan) }()

	wg.Add(1)
	go func() { defer wg.Done(); startAsyncWriter(ctx) }()

	wg.Add(1)
	go func() { defer wg.Done(); startCleaner(ctx) }()

	wg.Add(1)
	go func() { defer wg.Done(); startPinger(ctx) }()

	wg.Add(1)
	go func() { defer wg.Done(); startSSEBroker(ctx) }()

	if redisEnabled {
		wg.Add(1)
		go func() { defer wg.Done(); startRedisBroadcastListener(ctx) }()
	}

	// 定期刷新别名缓存
	wg.Add(1)
	go func() { defer wg.Done(); startCacheRefresher(ctx) }()

	// 定期预计算分析报告（仅 Redis 启用时）
	if redisEnabled {
		wg.Add(1)
		go func() { defer wg.Done(); startAnalysisPrecompute(ctx) }()
	}
}

// startCacheRefresher 定期刷新别名缓存
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

// gracefulShutdown 等待系统信号后有序关闭所有组件
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

// ================= 鉴权 =================

// extractToken 从 Authorization Header 或 Query 参数中提取 JWT
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

// authMiddleware JWT 鉴权中间件
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

// loginHandler 处理密码登录，成功时签发 JWT
func loginHandler(c *gin.Context) {
	ip := getClientIP(c)
	if loginRateLimiter.isRateLimited(ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录尝试过于频繁，请稍后再试"})
		return
	}

	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}

	if req.Password != AdminPassword {
		loginRateLimiter.recordFailure(ip)
		time.Sleep(500 * time.Millisecond)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}

	loginRateLimiter.recordSuccess(ip)

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

// checkAuthHandler 验证 Token 有效性
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

// metricsHandler 输出 Prometheus 格式的监控指标
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

// ================= HTTP 服务器 =================

// startHTTPServer 初始化 Gin 引擎、注册路由并启动监听
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
		ReadTimeout:  0, // 禁用读取超时以支持 SSE
		WriteTimeout: 0, // 禁用写入超时以支持 SSE
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

// corsMiddleware 设置跨域响应头
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

// setupAPIRoutes 注册所有 API 路由
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
			authorized.GET("/history", getPeerHistory)
			authorized.GET("/history/logs", getPeerAccessLogs)
			authorized.GET("/chart/traffic", getTrafficChartData)
			authorized.GET("/system", getSystemStatus)
			authorized.POST("/alias", setAlias)
			authorized.GET("/geoip", getGeoIPInfo)
			authorized.GET("/map/data", getMapData)
			authorized.GET("/analysis", getAdvancedAnalysis)
			authorized.GET("/ping/execute", pingHandler)
			authorized.GET("/traceroute/execute", tracerouteHandler)

			manage := authorized.Group("/manage")
			{
				manage.GET("/configs", listConfigFiles)
				manage.POST("/peer", addPeer)
				manage.DELETE("/peer", removePeer)
				manage.GET("/suggest_ip", suggestIPHandler)
				manage.POST("/peer/toggle", togglePeer)
			}
		}
	}
}

// ================= flag 解析辅助 =================

// parseFlags 解析命令行参数并读取环境变量覆盖
func parseFlags() {
	flag.StringVar(&WGInterface, "iface", "wg0", "WireGuard 接口名称")
	flag.StringVar(&ServerPort, "port", ":18080", "Web 监听端口")
	flag.StringVar(&MySQLDSN, "mysql", "wg_user:cloud123@tcp(127.0.0.1:3306)/wg_monitor?charset=utf8mb4&parseTime=True&loc=Local", "MySQL 连接字符串")
	flag.StringVar(&RedisAddr, "redis", "127.0.0.1:6379", "Redis 地址")
	flag.IntVar(&Retention, "days", 30, "数据保留天数")
	flag.StringVar(&AdminPassword, "password", "admin123", "仪表盘访问密码")
	flag.StringVar(&JWTSecret, "secret", "change_this_secret_in_prod", "JWT 签名密钥")
	flag.StringVar(&GeoCityPath, "geo-city", "./GeoLite2-City.mmdb", "GeoLite2 City 数据库路径")
	flag.StringVar(&GeoASNPath, "geo-asn", "./GeoLite2-ASN.mmdb", "GeoLite2 ASN 数据库路径")
	flag.Parse()

	// 环境变量优先级高于 flag 默认值
	if v := os.Getenv("WG_ADMIN_PASSWORD"); v != "" {
		AdminPassword = v
	}
	if v := os.Getenv("WG_JWT_SECRET"); v != "" {
		JWTSecret = v
	}
}
