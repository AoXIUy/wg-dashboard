package main

import (
	"context"
	_ "embed"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"wg-dashboard/pkg/config"
	"wg-dashboard/pkg/db"
	"wg-dashboard/pkg/handlers"
	"wg-dashboard/pkg/models"
	"wg-dashboard/pkg/service"
)

//go:embed index.html
var indexHtml string

// ================= 中间件 =================
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func jwtParse(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &models.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWTSecret), nil
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "需要认证"})
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		token, err := jwtParse(tokenString)

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "无效的令牌"})
			return
		}
		c.Next()
	}
}

// ================= 主程序 =================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[WG-Monitor] ")

	flag.StringVar(&config.WGInterface, "iface", "wg0", "WireGuard 接口名称")
	flag.StringVar(&config.ServerPort, "port", ":8080", "Web 监听端口")
	flag.StringVar(&config.MySQLDSN, "mysql", "root:password@tcp(127.0.0.1:3306)/wg_monitor?charset=utf8mb4&parseTime=True&loc=Local", "MySQL 连接字符串")
	flag.StringVar(&config.RedisAddr, "redis", "", "Redis 地址 (留空则禁用 Redis，使用进程内通讯)")
	flag.IntVar(&config.Retention, "days", 30, "数据保留天数")
	flag.StringVar(&config.AdminPassword, "password", "admin123", "仪表盘访问密码")
	flag.StringVar(&config.JWTSecret, "secret", "change_this_secret_in_prod", "JWT 签名密钥")
	flag.StringVar(&config.GeoCityPath, "geo-city", "./GeoLite2-City.mmdb", "GeoLite2 City 数据库路径")
	flag.StringVar(&config.GeoASNPath, "geo-asn", "./GeoLite2-ASN.mmdb", "GeoLite2 ASN 数据库路径")
	flag.Parse()

	// 初始化数据库
	if err := db.InitDB(config.MySQLDSN); err != nil {
		log.Fatalf("MySQL 连接失败: %v", err)
	}
	defer db.Close()

	// 初始化 Redis
	db.InitRedis(config.RedisAddr)

	// 初始化服务
	service.InitService()

	// 初始化 GeoIP
	service.InitGeoIP()

	// 启动后台任务
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dataChan := make(chan models.RawSnapshot, 2000)
	go service.StartCollector(ctx, dataChan)
	go service.StartProcessor(ctx, dataChan)
	go service.StartAsyncWriter(ctx)
	go service.StartCleaner(ctx)
	go service.StartRedisBroadcastListener(ctx)

	// Web 服务
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(corsMiddleware())

	// 静态文件
	r.Static("/static", "./static")
	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, indexHtml)
	})

	// API 路由
	api := r.Group("/api")
	{
		api.POST("/login", handlers.Login)
		api.GET("/status", handlers.GetSystemStatus)
		api.GET("/stream", handlers.StreamHandler)

		auth := api.Group("/")
		auth.Use(authMiddleware())
		{
			auth.GET("/peers", handlers.GetPeers)
			auth.GET("/analysis", handlers.GetAnalysisReport)
			auth.GET("/chart/traffic", handlers.GetTrafficChart)
			auth.POST("/peer", handlers.AddPeer)
			auth.GET("/history/:publickey", handlers.GetPeerHistory)
			auth.GET("/history/logs/:publickey", handlers.GetPeerLogs)
			auth.DELETE("/peer/:publickey", handlers.DeletePeer)
			auth.POST("/peer/:publickey/alias", handlers.UpdateAlias)
			auth.GET("/geoip", handlers.GetIPInfo)
		}
	}

	srv := &http.Server{
		Addr:    config.ServerPort,
		Handler: r,
	}

	go func() {
		log.Printf("==============================================")
		log.Printf("WireGuard Monitor & Manager 启动成功")
		log.Printf("接口: %s | 端口: %s", config.WGInterface, config.ServerPort)
		log.Printf("数据库: MySQL")
		log.Printf("==============================================")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Web 服务启动失败: %v", err)
		}
	}()

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭服务...")
	cancel()

	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancelShutdown()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		log.Fatal("服务强制关闭:", err)
	}

	service.CloseSharedWGClient()
	log.Println("服务已停止")
}