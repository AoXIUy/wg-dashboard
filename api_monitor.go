package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ================= 工具函数 =================

// getRangeParams 根据 period 字符串返回查询起始时间戳和聚合步长
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

// isValidConfigName 验证 WireGuard 配置名是否合法（字母数字下划线横线）
func isValidConfigName(name string) bool {
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return len(name) > 0
}

// ================= 监控 API Handler =================

// getSystemStatus 返回当前系统资源状态
func getSystemStatus(c *gin.Context) {
	sys := collectSystemInfo()
	c.JSON(http.StatusOK, sys)
}

// getPeers 返回所有 WireGuard Peer 的当前状态
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

// getPeerHistory 返回指定 Peer 的历史流量速率数据（按 period 聚合）
func getPeerHistory(c *gin.Context) {
	pk := c.Query("publickey")
	if pk == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 publickey 参数"})
		return
	}
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

// getPeerAccessLogs 返回指定 Peer 的会话级访问记录（最近 30 天，最多 100 条）
func getPeerAccessLogs(c *gin.Context) {
	pk := c.Query("publickey")
	if pk == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 publickey 参数"})
		return
	}
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

	var logs []AccessLog

	// 会话状态
	var sessionStart int64 = 0
	var sessionEnd int64 = 0
	var sessionEp string = ""
	var sessionRx int64 = 0
	var sessionTx int64 = 0
	var prevRx, prevTx int64 = -1, -1

	// 封卷当前会话
	flushSession := func() {
		if sessionStart == 0 || sessionEp == "" {
			return
		}

		timeStr := ""
		if sessionStart == sessionEnd {
			timeStr = time.Unix(sessionStart, 0).Format("2006-01-02 15:04")
		} else {
			startStr := time.Unix(sessionStart, 0).Format("2006-01-02 15:04")
			endStr := time.Unix(sessionEnd, 0).Format("15:04")
			if time.Unix(sessionStart, 0).YearDay() != time.Unix(sessionEnd, 0).YearDay() {
				endStr = time.Unix(sessionEnd, 0).Format("01-02 15:04")
			}
			timeStr = fmt.Sprintf("%s ~ %s", startStr, endStr)
		}

		logs = append(logs, AccessLog{
			Timestamp: timeStr,
			Endpoint:  sessionEp,
			RxTotal:   sessionRx,
			TxTotal:   sessionTx,
		})
	}

	cleanIP := func(ep string) string {
		host, _, err := net.SplitHostPort(ep)
		if err == nil {
			return host
		}
		return strings.Trim(ep, "[]")
	}

	for rows.Next() {
		var ts int64
		var ep string
		var rx, tx int64
		if err := rows.Scan(&ts, &ep, &rx, &tx); err != nil {
			continue
		}

		cleanEp := cleanIP(ep)

		if prevRx == -1 {
			prevRx = rx
			prevTx = tx
			sessionStart = ts
			sessionEnd = ts
			sessionEp = cleanEp
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

		timeGap := ts - sessionEnd
		if cleanEp != sessionEp || timeGap > 7200 { // 2 小时断层视为新会话
			flushSession()

			sessionStart = ts
			sessionEnd = ts
			sessionEp = cleanEp
			sessionRx = deltaRx
			sessionTx = deltaTx
		} else {
			sessionEnd = ts
			sessionRx += deltaRx
			sessionTx += deltaTx
		}

		prevRx = rx
		prevTx = tx
	}

	flushSession()

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据读取错误: " + err.Error()})
		return
	}

	// 倒序排列（最新记录在前）
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	if len(logs) > 100 {
		logs = logs[:100]
	}

	if logs == nil {
		logs = []AccessLog{}
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// getTrafficChartData 返回全局流量汇总图表数据
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

	buckets := make(map[int64]struct {
		rx, tx float64
		count  int
	})

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

// setAlias 设置或更新 Peer 别名
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

	aliasCache.Set(req.PublicKey, req.Alias)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// getGeoIPInfo 查询指定 IP 的地理信息
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

	if ipProvider != nil {
		info, err := ipProvider.GetInfo(ip)
		if err == nil {
			resp["country_code"] = info.CountryCode
			resp["city"] = info.City
			resp["latitude"] = info.Latitude
			resp["longitude"] = info.Longitude
			resp["asn"] = info.ASN
			resp["asn_number"] = info.ASNNumber
		}
	}

	c.JSON(http.StatusOK, resp)
}

// ================= 分析 API Handler =================

// getAnalysisHandler 返回 Peer 分析报告（支持 Redis 缓存）
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

// generateAnalysisReport 从数据库生成分析报告
func generateAnalysisReport(ctx context.Context, days int) (*AnalysisReport, error) {
	startTime := time.Now().AddDate(0, 0, -days).Unix()
	report := &AnalysisReport{}

	if aliasCache.NeedsRefresh() {
		aliasCache.Refresh(ctx)
	}

	// 获取实时 WireGuard 设备状态
	var livePeers map[string]wgtypes.Peer
	client, err := wgctrl.New()
	if err == nil {
		defer client.Close()
		device, err := client.Device(WGInterface)
		if err == nil {
			livePeers = make(map[string]wgtypes.Peer)
			for _, p := range device.Peers {
				livePeers[p.PublicKey.String()] = p
			}
		} else {
			logger.Printf("分析引擎: 无法获取接口 %s 信息: %v", WGInterface, err)
		}
	} else {
		logger.Printf("分析引擎: 无法连接 WG 控制器: %v", err)
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

		alias, ok := aliasCache.Get(pk)
		if !ok || alias == "" {
			var dbAlias string
			err := db.QueryRowContext(ctx, "SELECT alias FROM peer_aliases WHERE public_key = ?", pk).Scan(&dbAlias)
			if err == nil && dbAlias != "" {
				alias = dbAlias
				aliasCache.Set(pk, alias)
			}
		}

		var allowedIPs []string
		var endpointStr string
		var latestHandshake int64
		var city, countryCode string

		if lp, ok := livePeers[pk]; ok {
			for _, ip := range lp.AllowedIPs {
				allowedIPs = append(allowedIPs, ip.String())
			}
			if lp.Endpoint != nil {
				endpointStr = lp.Endpoint.String()
			}
			latestHandshake = lp.LastHandshakeTime.Unix()
		}

		isOnline := time.Since(time.Unix(latestHandshake, 0)) < 3*time.Minute

		if endpointStr == "" {
			var lastEp string
			db.QueryRowContext(ctx, "SELECT endpoint FROM traffic_history WHERE peer_public_key = ? AND endpoint != '' ORDER BY timestamp DESC LIMIT 1", pk).Scan(&lastEp)
			endpointStr = lastEp
		}

		var latitude, longitude float64
		if endpointStr != "" {
			host, _, _ := net.SplitHostPort(endpointStr)
			if host == "" {
				host = endpointStr
			}
			ip := net.ParseIP(host)
			if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && ipProvider != nil {
				if info, err := ipProvider.GetInfo(ip); err == nil {
					city = info.City
					countryCode = info.CountryCode
					latitude = info.Latitude
					longitude = info.Longitude
				}
			}
		}

		report.Peers = append(report.Peers, PeerAnalysis{
			PublicKey:       pk,
			Alias:           alias,
			TotalRx:         estRx,
			TotalTx:         estTx,
			Uptime:          uptime,
			HealthScore:     score,
			LastSeenTime:    lastSeen,
			AllowedIPs:      allowedIPs,
			Endpoint:        endpointStr,
			City:            city,
			CountryCode:     countryCode,
			Latitude:        latitude,
			Longitude:       longitude,
			Latency:         latencyCache.Get(pk),
			LatestHandshake: latestHandshake,
			IsOnline:        isOnline,
		})
	}

	if err := pRows.Err(); err != nil {
		return nil, fmt.Errorf("Peer 数据读取错误: %w", err)
	}

	sort.Slice(report.Peers, func(i, j int) bool {
		return (report.Peers[i].TotalRx + report.Peers[i].TotalTx) > (report.Peers[j].TotalRx + report.Peers[j].TotalTx)
	})

	// 小时活动分析
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
			if cnt := hourCount[i]; cnt > 0 {
				avg = hourMap[i] / float64(cnt)
			}
			report.HourlyProfile = append(report.HourlyProfile, ActivityPoint{Hour: i, RxSum: avg, TxSum: 0})
		}
	}

	return report, nil
}

// getAnalysisReport 先查 Redis 缓存，未命中时调用 generateAnalysisReport
func getAnalysisReport(c *gin.Context, days int) (*AnalysisReport, error) {
	if !redisEnabled {
		report, err := generateAnalysisReport(c.Request.Context(), days)
		if err == nil {
			c.Header("X-Cache", "DISABLED")
		}
		return report, err
	}

	cacheKey := fmt.Sprintf("wg:cache:analysis:%d", days)

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

	report, err := generateAnalysisReport(c.Request.Context(), days)
	if err == nil {
		jsonBytes, _ := json.Marshal(report)
		rdb.Set(c.Request.Context(), cacheKey, jsonBytes, 1*time.Minute)
		c.Header("X-Cache", "MISS")
	}

	return report, err
}
