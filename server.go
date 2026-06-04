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
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "modernc.org/sqlite"

	"wg-dashboard/pkg/ipapi"
)

// ================= 日志系统 =================

// initLogger 初始化日志系统，同时输出到文件（轮转）和控制台
func initLogger() {
	logFile := &lumberjack.Logger{
		Filename:   "./app.log",
		MaxSize:    50,   // RK3399 优化：从 100MB 降到 50MB
		MaxBackups: 3,    // 从 7 个降到 3 个
		MaxAge:     14,   // 从 30 天降到 14 天
		Compress:   true, // 压缩旧日志
		LocalTime:  true, // 使用本地时间
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(multiWriter, "[WG-Monitor] ", log.LstdFlags|log.Lshortfile)

	logger.Println("日志系统初始化完成，日志将输出到 app.log")
}

// ================= 初始化辅助 =================

// initGeoIP 根据命令行参数加载地理 IP 数据库
// 优先级：ip2region xdb（中国优化）> GeoLite2-City > 外部 API 回退
// 各数据源均为可选，缺失时自动降级，不影响程序启动
func initGeoIP() {
	var providers []ipapi.Provider

	// ① ip2region v2 xdb（专为中国 IPv4/IPv6 优化，优先级最高）
	if _, err := os.Stat(GeoXDBPath); err == nil {
		xdbProvider, err := ipapi.NewIP2RegionProvider(GeoXDBPath)
		if err != nil {
			logger.Printf("ip2region xdb 初始化失败: %v", err)
		} else {
			providers = append(providers, xdbProvider)
			logger.Printf("ip2region xdb 已加载: %s", GeoXDBPath)
		}
	} else {
		logger.Printf("ip2region xdb 不存在，跳过: %s（可从 https://github.com/lionsoul2014/ip2region 下载）", GeoXDBPath)
	}

	// ② GeoLite2-City + ASN（国际 IP 回退）
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
		// 启用外部 API 回退（修复后：城市为空时才触发，不再被 CountryCode 短路）
		geoLite2Provider, err := ipapi.NewGeoLite2Provider(cityPath, asnPath, true)
		if err != nil {
			logger.Printf("GeoLite2 初始化失败: %v", err)
		} else {
			providers = append(providers, geoLite2Provider)
			logger.Println("GeoLite2 数据库已加载")
		}
	}

	// 组合所有可用 Provider（至少有一个才启用）
	if len(providers) > 0 {
		ipProvider = ipapi.NewChainProvider(providers...)
		logger.Printf("GeoIP 链式 Provider 已就绪，共 %d 个数据源", len(providers))
	} else {
		logger.Println("警告：所有 GeoIP 数据源均不可用，IP 地理位置功能已禁用")
	}
}

// initComponents 初始化所有内存组件（缓存、SSE Broker 等）
func initComponents() {
	aliasCache = NewAliasCache(CacheTTL)
	trafficBuffer = NewTrafficBuffer(BufferMaxSize)
	latencyCache = NewLatencyCache()
	metrics = &Metrics{}

	// 初始化内存状态缓存（替代 Redis）
	initStateCache()

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

	// 定期刷新别名缓存
	wg.Add(1)
	go func() { defer wg.Done(); startCacheRefresher(ctx) }()

	// 定期清理地理信息内存缓存（防止内存泄漏）
	wg.Add(1)
	go func() { defer wg.Done(); startGeoCacheCleaner(ctx) }()

	// 预计算分析报告（始终启用，使用内存缓存替代 Redis）
	wg.Add(1)
	go func() { defer wg.Done(); startAnalysisPrecompute(ctx) }()

	// RK3399 优化：数据降采样引擎
	wg.Add(1)
	go func() { defer wg.Done(); startDownsampler(ctx) }()

	// RK3399 优化：SQLite 维护任务
	wg.Add(1)
	go func() { defer wg.Done(); startSQLiteMaintenance(ctx) }()

	// RK3399 优化：系统指标异步采集器
	wg.Add(1)
	go func() { defer wg.Done(); startSysInfoCollector(ctx) }()
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
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("无效的签名方法")
		}
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

# HELP wg_failed_writes_total Failed SQLite writes
# TYPE wg_failed_writes_total counter
wg_failed_writes_total %d

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
		logger.Printf("数据库: SQLite (WAL 模式) | 路径: %s", DBPath)
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
			authorized.GET("/metrics", metricsHandler)

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
	flag.StringVar(&DBPath, "db", "./wg-dashboard.db", "SQLite 数据库路径")
	flag.IntVar(&Retention, "days", 30, "数据保留天数")
	flag.StringVar(&AdminPassword, "password", "", "仪表盘访问密码 (必填，或设置 WG_ADMIN_PASSWORD 环境变量)")
	flag.StringVar(&JWTSecret, "secret", "", "JWT 签名密钥 (必填，或设置 WG_JWT_SECRET 环境变量)")
	flag.StringVar(&GeoCityPath, "geo-city", "./GeoLite2-City.mmdb", "GeoLite2 City 数据库路径")
	flag.StringVar(&GeoASNPath, "geo-asn", "./GeoLite2-ASN.mmdb", "GeoLite2 ASN 数据库路径")
	flag.StringVar(&GeoXDBPath, "geo-xdb", "./ip2region.xdb", "ip2region v2 数据库路径（可选，专为中国 IPv4/IPv6 城市解析优化）")
	flag.Parse()

	// 环境变量优先级高于 flag
	if v := os.Getenv("WG_ADMIN_PASSWORD"); v != "" {
		AdminPassword = v
	}
	if v := os.Getenv("WG_JWT_SECRET"); v != "" {
		JWTSecret = v
	}
	if v := os.Getenv("WG_DB_PATH"); v != "" {
		DBPath = v
	}

	// 安全校验
	validateSecurityConfig()
}

// validateSecurityConfig 校验安全关键配置，不满足时直接终止程序
func validateSecurityConfig() {
	if AdminPassword == "" {
		logger.Fatal("[安全] 密码未设置，请通过 -password 参数或 WG_ADMIN_PASSWORD 环境变量配置")
	}
	if len(AdminPassword) < 8 {
		logger.Fatal("[安全] 密码长度不足 8 位，请设置更强的密码")
	}
	if JWTSecret == "" {
		logger.Fatal("[安全] JWT 密钥未设置，请通过 -secret 参数或 WG_JWT_SECRET 环境变量配置")
	}
	if len(JWTSecret) < 16 {
		logger.Fatal("[安全] JWT 密钥长度不足 16 位，请使用更长的随机字串")
	}
}
