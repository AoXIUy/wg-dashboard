package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestE2E_FullMockWorkflow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 设置沙盒测试目录
	testDir := filepath.Join(SandboxDataDir, "e2e_test")
	_ = os.RemoveAll(testDir)
	_ = os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	DBPath = filepath.Join(testDir, "e2e.db")
	WGConfigDir = filepath.Join(testDir, "configs")
	WGInterface = "wg0"
	AdminPassword = "test_password_123"
	JWTSecret = "super_secret_jwt_key_at_least_16_bytes"
	Retention = 30
	IsMockMode = true

	// 初始化组件
	InitExecutor()
	initMemoryEngine()
	initComponents()

	if err := initDB(); err != nil {
		t.Fatalf("initDB failed: %v", err)
	}
	defer closeDB()

	// 初始加载别名
	_ = aliasCache.Refresh(context.Background())

	// 构建路由引擎
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

	if subFS, err := os.ReadDir("./static"); err == nil && len(subFS) > 0 {
		r.Static("/static", "./static")
	}

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, indexHtml)
	})

	setupAPIRoutes(r)

	// 绑定到随机空闲高端口 (127.0.0.1:0)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test listener: %v", err)
	}
	defer listener.Close()

	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())
	srv := &http.Server{Handler: r}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. 测试 GET / (嵌入的前端页面)
	t.Run("GET / Root HTML", func(t *testing.T) {
		resp, err := client.Get(serverURL + "/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "WireGuard") {
			t.Errorf("HTML should mention WireGuard")
		}
	})

	// 2. 测试 POST /api/login (错误密码 -> 401)
	t.Run("POST /api/login Failed", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"password": "wrong_password"})
		resp, err := client.Post(serverURL+"/api/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	// 3. 测试 POST /api/login (正确密码 -> 200 + JWT Token)
	var authToken string
	t.Run("POST /api/login Success", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"password": AdminPassword})
		resp, err := client.Post(serverURL+"/api/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		var res map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		token, ok := res["token"].(string)
		if !ok || token == "" {
			t.Fatalf("token missing in login response")
		}
		authToken = token
	})

	authHeader := "Bearer " + authToken

	// 4. 测试 GET /api/check_auth
	t.Run("GET /api/check_auth", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/check_auth", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("check_auth failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	// 5. 测试 GET /api/peers
	t.Run("GET /api/peers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/peers", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("get peers failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var res map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		peers, ok := res["peers"].([]interface{})
		if !ok || len(peers) == 0 {
			t.Errorf("expected simulated mock peers, got %v", res)
		}
	})

	// 6. 测试 GET /api/manage/configs
	t.Run("GET /api/manage/configs", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/manage/configs", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("list configs failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var res map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		configs, ok := res["configs"].([]interface{})
		if !ok || len(configs) == 0 {
			t.Errorf("expected at least one config file, got %v", res)
		}
	})

	// 7. 测试 GET /api/manage/suggest_ip
	t.Run("GET /api/manage/suggest_ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/manage/suggest_ip?config=wg0", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("suggest ip failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var res map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&res)
		ip, ok := res["ip"].(string)
		if !ok || !strings.Contains(ip, "/32") {
			t.Errorf("expected suggested IP ending in /32, got %v", res)
		}
	})

	// 8. 测试 POST /api/alias
	t.Run("POST /api/alias", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"public_key": "some_dummy_key_1234567890123456789012345678=",
			"alias":      "My-New-Server",
		})
		req, _ := http.NewRequest("POST", serverURL+"/api/alias", bytes.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("set alias failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	// 9. 测试 GET /api/ping/execute
	t.Run("GET /api/ping/execute", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/ping/execute?ipAddress=10.0.0.2&count=2", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("ping execute failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var res PingResponse
		_ = json.NewDecoder(resp.Body).Decode(&res)
		if !res.IsAlive {
			t.Errorf("expected alive ping in mock mode, got %+v", res)
		}
	})

	// 10. 测试 GET /api/traceroute/execute
	t.Run("GET /api/traceroute/execute", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/traceroute/execute?ipAddress=10.0.0.2", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("traceroute execute failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		var res TracerouteResponse
		_ = json.NewDecoder(resp.Body).Decode(&res)
		if len(res.Hops) == 0 {
			t.Errorf("expected hops in mock traceroute, got %+v", res)
		}
	})

	// 11. 测试 GET /api/metrics (Prometheus 格式)
	t.Run("GET /api/metrics", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/metrics", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("metrics request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "wg_processed_total") {
			t.Errorf("expected Prometheus metric wg_processed_total, got:\n%s", string(body))
		}
	})

	// 12. 测试 GET /api/analysis
	t.Run("GET /api/analysis", func(t *testing.T) {
		req, _ := http.NewRequest("GET", serverURL+"/api/analysis", nil)
		req.Header.Set("Authorization", authHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("analysis request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}
