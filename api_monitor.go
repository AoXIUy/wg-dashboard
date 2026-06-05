package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
// BUG-1：改读异步缓存，避免每次请求同步等待 CPU 采样（在 RK3399 上可能阻塞 ~1s）
func getSystemStatus(c *gin.Context) {
	sys := getCachedSystemInfo()
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

	// 如果原始表无数据（已降采样），从聚合表补充长时间段数据
	if len(buckets) == 0 && (period == "24h" || period == "7d") {
		rows2, err := db.QueryContext(ctx, `
			SELECT hour_ts, avg_rx_rate, avg_tx_rate 
			FROM traffic_hourly 
			WHERE peer_key = ? AND hour_ts >= ? 
			ORDER BY hour_ts ASC
		`, pk, startTime)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var ts int64
				var rx, tx float64
				if err := rows2.Scan(&ts, &rx, &tx); err != nil {
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
		}
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

	// 如果原始表无数据（已降采样），从聚合表补充
	if len(buckets) == 0 && (period == "24h" || period == "7d") {
		rows2, err := db.QueryContext(ctx, `
			SELECT hour_ts, SUM(avg_rx_rate), SUM(avg_tx_rate) 
			FROM traffic_hourly 
			WHERE hour_ts >= ? 
			GROUP BY hour_ts 
			ORDER BY hour_ts ASC
		`, startTime)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var ts int64
				var rx, tx float64
				if err := rows2.Scan(&ts, &rx, &tx); err != nil {
					continue
				}
				slot := (ts / step) * step
				b := buckets[slot]
				b.rx += rx
				b.tx += tx
				b.count++
				buckets[slot] = b
			}
		}
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

// setAlias 设置或更新 Peer 别名（SQLite 兼容：ON CONFLICT 替代 ON DUPLICATE KEY UPDATE）
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
		ON CONFLICT(public_key) DO UPDATE SET alias = excluded.alias
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

// generateAnalysisReport 从数据库生成分析报告
// 注：此函数当前为备用实现，已注册路由使用 analysisEngine.GetAdvancedReport()。
func generateAnalysisReport(ctx context.Context, days int) (*AnalysisReport, error) {
	startTime := time.Now().AddDate(0, 0, -days).Unix()
	report := &AnalysisReport{}

	if aliasCache.NeedsRefresh() {
		aliasCache.Refresh(ctx)
	}

	// BUG-6：直接读取全局 Peer 缓存，避免重复向 WireGuard 内核发起查询
	cachedPeersMu.RLock()
	livePeers := make(map[string]PeerData, len(cachedPeers))
	for _, p := range cachedPeers {
		livePeers[p.PublicKey] = p
	}
	cachedPeersMu.RUnlock()

	// PERF-4：预取各 Peer 最新 endpoint，避免循环内 N+1 数据库查询
	lastEpMap := make(map[string]string)
	if epRows, epErr := db.QueryContext(ctx, `
		SELECT peer_public_key, endpoint
		FROM traffic_history
		WHERE rowid IN (
			SELECT MAX(rowid) FROM traffic_history
			WHERE endpoint != '' AND timestamp > ?
			GROUP BY peer_public_key
		)
	`, startTime); epErr == nil {
		defer epRows.Close()
		for epRows.Next() {
			var epk, ep string
			if epRows.Scan(&epk, &ep) == nil {
				lastEpMap[epk] = ep
			}
		}
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

		estRx := int64(rxSum * 5.0 * 1000000 / 8) // 5 秒窗口（匹配 CollectInterval）
		estTx := int64(txSum * 5.0 * 1000000 / 8)

		uptime := (onlineSum / float64(count)) * 100
		score := int(uptime)
		if lastSeen < time.Now().Add(-24*time.Hour).Unix() {
			score -= 30
		}
		if score < 0 {
			score = 0
		}

		alias, _ := aliasCache.Get(pk)

		var allowedIPs []string
		var endpointStr string
		var latestHandshake int64
		var city, countryCode string

		if lp, ok := livePeers[pk]; ok {
			allowedIPs = lp.AllowedIPs
			endpointStr = lp.Endpoint
			latestHandshake = lp.LatestHandshake
		}

		isOnline := time.Since(time.Unix(latestHandshake, 0)) < 3*time.Minute

		// PERF-4：使用预取的 lastEpMap，无需循环内 N+1 查询
		if endpointStr == "" {
			endpointStr = lastEpMap[pk]
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
