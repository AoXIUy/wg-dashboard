package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupTestBackupRouter(t *testing.T) *gin.Engine {
	gin.SetMode(gin.TestMode)

	// 设置测试沙盒数据库
	testDir := filepath.Join(SandboxDataDir, "test_backup")
	_ = os.RemoveAll(testDir)
	_ = os.MkdirAll(testDir, 0755)

	DBPath = filepath.Join(testDir, "backup_test.db")
	_ = initDB()

	initMemoryEngine()
	initComponents()

	AdminPassword = "test-backup-password"
	JWTSecret = "test-backup-secret"

	r := gin.New()
	setupAPIRoutes(r)
	return r
}

func TestBackup_ExportImportAndStats(t *testing.T) {
	r := setupTestBackupRouter(t)

	// 1. 获取登录 Token
	loginBody, _ := json.Marshal(map[string]string{"password": "test-backup-password"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("登录失败: %d, %s", w.Code, w.Body.String())
	}

	var loginResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &loginResp)
	token := loginResp["token"]
	if token == "" {
		t.Fatal("未获取到 token")
	}

	// 2. 测试初始 Stats
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/backup/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("获取 Stats 失败: %d", w.Code)
	}

	var stats DatabaseStats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("解析 Stats 失败: %v", err)
	}
	if stats.PeerAliasesCount != 0 {
		t.Errorf("初始别名数量应为 0, 实际: %d", stats.PeerAliasesCount)
	}

	// 3. 测试导入 Backup
	importData := BackupData{
		Version: "1.0",
		Aliases: []PeerAliasRecord{
			{PublicKey: "PkAlpha11111111111111111111111111111111111=", Alias: "Alice Phone", Enabled: true},
			{PublicKey: "PkBeta222222222222222222222222222222222222=", Alias: "Bob Laptop", Enabled: false},
		},
		Configs: []PeerConfigRecord{
			{PublicKey: "PkBeta222222222222222222222222222222222222=", ConfName: "wg0", PeerBlock: "[Peer]\nPublicKey = PkBeta222222222222222222222222222222222222=\nAllowedIPs = 10.0.0.2/32\n", SavedAt: 1700000000},
		},
	}
	body, _ := json.Marshal(importData)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("导入失败: %d, %s", w.Code, w.Body.String())
	}

	var importResult map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &importResult)
	if importResult["imported_aliases"] != float64(2) {
		t.Errorf("预期导入 2 个别名, 实际: %v", importResult["imported_aliases"])
	}
	if importResult["imported_configs"] != float64(1) {
		t.Errorf("预期导入 1 个配置, 实际: %v", importResult["imported_configs"])
	}

	// 4. 验证内存缓存是否同步更新
	if cached, ok := aliasCache.Get("PkAlpha11111111111111111111111111111111111="); !ok || cached != "Alice Phone" {
		t.Errorf("别名内存缓存预期 'Alice Phone', 实际: '%s' (ok=%v)", cached, ok)
	}
	if enabled := aliasCache.GetEnabled("PkBeta222222222222222222222222222222222222="); enabled {
		t.Errorf("预期 PkBeta 为 disabled(false), 实际为 true")
	}

	// 5. 测试导出 Backup
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/backup/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("导出失败: %d, %s", w.Code, w.Body.String())
	}

	var exported BackupData
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatalf("解析导出数据失败: %v", err)
	}
	if len(exported.Aliases) != 2 {
		t.Errorf("导出别名数量预期 2, 实际: %d", len(exported.Aliases))
	}
	if len(exported.Configs) != 1 {
		t.Errorf("导出配置数量预期 1, 实际: %d", len(exported.Configs))
	}

	// 6. 再次检查 Stats
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/backup/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	_ = json.Unmarshal(w.Body.Bytes(), &stats)
	if stats.PeerAliasesCount != 2 {
		t.Errorf("导入后别名统计预期 2, 实际: %d", stats.PeerAliasesCount)
	}
	if stats.PeerConfigsCount != 1 {
		t.Errorf("导入后配置统计预期 1, 实际: %d", stats.PeerConfigsCount)
	}
}
