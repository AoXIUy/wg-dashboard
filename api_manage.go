package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ================= 配置管理 API =================

// listConfigFiles 列出 /etc/wireguard/ 下所有 .conf 文件名
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

// addPeer 生成密钥对并将新 Peer 添加到指定配置文件，热重载 WireGuard
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

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 正确性修复：记录别名写库错误（非致命，Peer 仍可正常连接）
	if _, dbErr := db.ExecContext(ctx, `
		INSERT INTO peer_aliases (public_key, alias) 
		VALUES (?, ?) 
		ON DUPLICATE KEY UPDATE alias = VALUES(alias)
	`, pubKey.String(), req.Name); dbErr != nil {
		logger.Printf("[addPeer] 写入别名失败 (公钥 %s): %v", pubKey.String()[:8], dbErr)
	}

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

// removePeer 从配置文件删除 Peer 并清理数据库记录
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

	ctx := context.Background()

	_, err := db.ExecContext(ctx, "DELETE FROM peer_aliases WHERE public_key = ?", pubKey)
	if err != nil {
		logger.Printf("删除别名失败: %v", err)
	}

	result, err := db.ExecContext(ctx, "DELETE FROM traffic_history WHERE peer_public_key = ?", pubKey)
	if err != nil {
		logger.Printf("删除流量历史失败: %v", err)
	} else if rows, _ := result.RowsAffected(); rows > 0 {
		logger.Printf("已删除客户端 %s 的 %d 条历史记录", pubKey[:8], rows)
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// togglePeer 切换客户端的内核层启用/禁用状态
// 禁用：提取 peer 块 → 存入 peer_configs → 从 conf 移除 → wg syncconf
// 启用：从 peer_configs 读取 → 追加到 conf → wg syncconf → 清理 peer_configs
func togglePeer(c *gin.Context) {
	var req struct {
		PublicKey string `json:"public_key"`
		Enabled   bool   `json:"enabled"`
		ConfName  string `json:"conf_name"` // 可选，不传时使用全局 WGInterface
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	if len(req.PublicKey) > MaxPublicKeyLength || !publicKeyRegex.MatchString(req.PublicKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的公鑰格式"})
		return
	}

	confName := req.ConfName
	if confName == "" {
		confName = WGInterface
	}
	if !isValidConfigName(confName) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "非法配置名"})
		return
	}

	configMu.Lock()
	defer configMu.Unlock()

	dbCtx, dbCancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer dbCancel()

	if req.Enabled {
		// ======== 启用：从 DB 读取配置块并写回 conf ========
		var peerBlock, savedConf string
		err := db.QueryRowContext(dbCtx,
			"SELECT peer_block, conf_name FROM peer_configs WHERE public_key = ?", req.PublicKey,
		).Scan(&peerBlock, &savedConf)

		if err == sql.ErrNoRows {
			logger.Printf("[togglePeer] peer %s 在 peer_configs 中未找到配置，仅更新 DB 标记", req.PublicKey[:8])
			_, _ = db.ExecContext(dbCtx, `INSERT INTO peer_aliases (public_key, alias, enabled) VALUES (?, '', 1) ON DUPLICATE KEY UPDATE enabled = 1`, req.PublicKey)
			aliasCache.SetEnabled(req.PublicKey, true)
			c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": true, "note": "no_saved_config"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取已存配置失败: " + err.Error()})
			return
		}

		if savedConf != "" {
			confName = savedConf
		}

		confPath := fmt.Sprintf("/etc/wireguard/%s.conf", confName)
		f, err := os.OpenFile(confPath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开配置文件: " + err.Error()})
			return
		}
		_, writeErr := fmt.Fprintln(f, "\n"+peerBlock)
		f.Close()
		if writeErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置失败"})
			return
		}

		if err := reloadWireGuard(confName); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "wg syncconf 失败: " + err.Error()})
			return
		}

		if _, dbErr := db.ExecContext(dbCtx, "DELETE FROM peer_configs WHERE public_key = ?", req.PublicKey); dbErr != nil {
			logger.Printf("[togglePeer] 清理 peer_configs 失败 (公钥 %s): %v", req.PublicKey[:8], dbErr)
		}
		if _, dbErr := db.ExecContext(dbCtx, `INSERT INTO peer_aliases (public_key, alias, enabled) VALUES (?, '', 1) ON DUPLICATE KEY UPDATE enabled = 1`, req.PublicKey); dbErr != nil {
			logger.Printf("[togglePeer] 更新 peer_aliases.enabled=1 失败 (公钥 %s): %v", req.PublicKey[:8], dbErr)
		}
		aliasCache.SetEnabled(req.PublicKey, true)

		logger.Printf("[togglePeer] Peer %s 已启用 (wg syncconf 热重载)", req.PublicKey[:8])
		c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": true})
		return
	}

	// ======== 禁用：提取 peer 块 → 存 DB → 从 conf 移除 → syncconf ========
	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", confName)

	peerBlock, err := extractPeerBlock(confPath, req.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提取 peer 配置失败: " + err.Error()})
		return
	}
	if peerBlock == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到该 peer 的配置块，可能已禁用"})
		return
	}

	_, err = db.ExecContext(dbCtx, `
		INSERT INTO peer_configs (public_key, conf_name, peer_block, saved_at)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE conf_name = VALUES(conf_name), peer_block = VALUES(peer_block), saved_at = VALUES(saved_at)
	`, req.PublicKey, confName, peerBlock, time.Now().Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "存储配置失败: " + err.Error()})
		return
	}

	if err := modifyConfigFile(confName, req.PublicKey, "remove"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改配置文件失败: " + err.Error()})
		return
	}

	if err := reloadWireGuard(confName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "wg syncconf 失败: " + err.Error()})
		return
	}

	if _, dbErr := db.ExecContext(dbCtx, `INSERT INTO peer_aliases (public_key, alias, enabled) VALUES (?, '', 0) ON DUPLICATE KEY UPDATE enabled = 0`, req.PublicKey); dbErr != nil {
		logger.Printf("[togglePeer] 更新 peer_aliases.enabled=0 失败 (公钥 %s): %v", req.PublicKey[:8], dbErr)
	}
	aliasCache.SetEnabled(req.PublicKey, false)

	logger.Printf("[togglePeer] Peer %s 已禁用 (wg syncconf 热重载)", req.PublicKey[:8])
	c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": false})
}

// suggestIPHandler 根据配置文件已用 IP 推荐一个未使用的 /32 地址
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

// ================= WireGuard 配置文件操作 =================

// reloadWireGuard 使用 wg-quick strip + wg syncconf 热重载指定接口
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

// extractPeerBlock 从 wg conf 文件中提取指定 Peer 的完整配置块（含 # Name: 注释）
func extractPeerBlock(confPath, pubKey string) (string, error) {
	content, err := os.ReadFile(confPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var blockLines []string
	inTarget := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)

		if trim == "[Peer]" {
			isTarget := false
			for j := i + 1; j < len(lines) && j < i+15; j++ {
				if strings.Contains(lines[j], pubKey) {
					isTarget = true
					break
				}
				if strings.TrimSpace(lines[j]) == "[Peer]" || strings.TrimSpace(lines[j]) == "[Interface]" {
					break
				}
			}
			if isTarget {
				inTarget = true
				if i > 0 && strings.HasPrefix(strings.TrimSpace(lines[i-1]), "# Name:") {
					blockLines = append(blockLines, lines[i-1])
				}
				blockLines = append(blockLines, line)
				continue
			}
		}

		if inTarget {
			if strings.HasPrefix(trim, "[") && trim != "[Peer]" {
				break
			}
			if trim == "" && i+1 < len(lines) {
				next := strings.TrimSpace(lines[i+1])
				if strings.HasPrefix(next, "[") {
					break
				}
			}
			blockLines = append(blockLines, line)
		}
	}

	if !inTarget {
		return "", nil
	}

	// 去掉末尾空行
	for len(blockLines) > 0 && strings.TrimSpace(blockLines[len(blockLines)-1]) == "" {
		blockLines = blockLines[:len(blockLines)-1]
	}

	return strings.Join(blockLines, "\n"), nil
}

// modifyConfigFile 对配置文件执行指定操作（目前仅支持 "remove"）
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

	// 原子性修复：先写临时文件，再 Rename，防止崩溃导致配置损坏
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(output), 0600); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath) // 清理临时文件
		return fmt.Errorf("原子替换配置文件失败: %w", err)
	}
	return nil
}
