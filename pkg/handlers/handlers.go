package handlers

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"wg-dashboard/pkg/config"
	"wg-dashboard/pkg/db"
	"wg-dashboard/pkg/models"
	"wg-dashboard/pkg/service"
)

// Login Handler
func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}

	if req.Password != config.AdminPassword {
		time.Sleep(500 * time.Millisecond)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}

	expirationTime := time.Now().Add(config.TokenExpireDuration)
	claims := &models.JwtClaims{
		User: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "wg-monitor",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_at": expirationTime.Unix(),
	})
}

// GetSystemStatus Handler
func GetSystemStatus(c *gin.Context) {
	sys := service.CollectSystemInfo()
	c.JSON(http.StatusOK, sys)
}

// GetPeers Handler
func GetPeers(c *gin.Context) {
	peers, name, port, err := service.CollectPeersData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取设备信息"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"interface": name,
		"port":      port,
		"peers":     peers,
	})
}

// GetAnalysisReport Handler
func GetAnalysisReport(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		days = 7
	}

	// 尝试从 Redis 获取缓存
	cacheKey := "wg:cache:analysis:" + strconv.Itoa(days)
	var report models.AnalysisReport
	if db.GetCache(c.Request.Context(), cacheKey, &report) == nil {
		c.Header("X-Cache", "HIT")
		c.JSON(http.StatusOK, report)
		return
	}

	// 缓存未命中，调用 Service 生成
	report, err = service.GenerateAnalysisReport(c.Request.Context(), days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成报告失败"})
		return
	}
	c.JSON(http.StatusOK, report)
}

// StreamHandler Handler
func StreamHandler(c *gin.Context) {
	clientChan := service.RegisterSSEClient()
	defer service.UnregisterSSEClient(clientChan)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")

	c.Stream(func(w io.Writer) bool {
		return service.GetSSEStream(w, clientChan)
	})
}

// AddPeer Handler
func AddPeer(c *gin.Context) {
	var req models.AddPeerRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	// 基本验证
	if req.ConfigFile == "" || !service.IsValidConfigName(req.ConfigFile) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法配置名"})
		return
	}

	// 生成密钥
	pKey, pubKey, presharedKey, err := service.GeneratePeerKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成密钥失败"})
		return
	}

	// 写入配置文件
	confPath := "/etc/wireguard/" + req.ConfigFile + ".conf"
	f, err := os.OpenFile(confPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开配置文件(Permission?)"})
		return
	}
	defer f.Close()

	peerBlock := "\n# Name: " + req.Name + "\n[Peer]\nPublicKey = " + pubKey + "\nPresharedKey = " + presharedKey + "\nAllowedIPs = " + req.AllowedIPs + "\n"
	if _, err := f.WriteString(peerBlock); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置失败"})
		return
	}

	// 保存别名
	db.SaveAlias(pubKey, req.Name)

	// 重载 WG
	if err := service.ReloadWireGuard(req.ConfigFile); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "saved_but_reload_failed", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":            "ok",
		"private_key":       pKey,
		"public_key":        pubKey,
		"preshared_key":     presharedKey,
		"config_file":       req.ConfigFile,
	})
}

// GetTrafficChart Handler
func GetTrafficChart(c *gin.Context) {
	period := c.DefaultQuery("period", "realtime")
	chartData, err := service.GetGlobalTrafficChart(period)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}
	c.JSON(http.StatusOK, chartData)
}

// GetPeerHistory Handler
func GetPeerHistory(c *gin.Context) {
	pk := c.Param("publickey")
	period := c.DefaultQuery("period", "realtime")

	history, err := service.GetPeerHistory(pk, period)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询失败"})
		return
	}

	c.JSON(http.StatusOK, history)
}

// DeletePeer Handler
func DeletePeer(c *gin.Context) {
	pk := c.Param("publickey")
	if err := service.RemovePeer(pk); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// UpdateAlias Handler
func UpdateAlias(c *gin.Context) {
	pk := c.Param("publickey")
	var req struct {
		Alias string `json:"alias"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	if err := service.UpdateAlias(pk, req.Alias); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetIPInfo Handler
func GetIPInfo(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP is required"})
		return
	}
	info := service.LookupIP(ip)
	c.JSON(http.StatusOK, info)
}
