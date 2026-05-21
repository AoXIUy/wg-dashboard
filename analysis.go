package main

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"time"
)

// ================= 分析引擎结构 =================

type AnalysisEngine struct {
	db *sql.DB
}

func NewAnalysisEngine(db *sql.DB) *AnalysisEngine {
	return &AnalysisEngine{db: db}
}

// ================= 数据结构 =================

type AnomalyEvent struct {
	PublicKey string    `json:"public_key"`
	Type      string    `json:"type"`     // "traffic_spike", "network_abuse"
	Severity  string    `json:"severity"` // "medium", "high"
	Message   string    `json:"message"`
	Time      time.Time `json:"time"`
}

type ChurnRisk struct {
	PublicKey   string  `json:"public_key"`
	RiskScore   float64 `json:"risk_score"`   // 0-100
	RiskLevel   string  `json:"risk_level"`   // "low", "medium", "high", "churned"
	DaysOffline int     `json:"days_offline"` // 连续离线天数
	TrendSlope  float64 `json:"trend_slope"`  // 流量趋势斜率
}

type OptimalTime struct {
	StartHour   int     `json:"start_hour"`
	EndHour     int     `json:"end_hour"`
	AvgLoadMbps float64 `json:"avg_load_mbps"`
}

type HourlyTraffic struct {
	Hour  int     `json:"hour"`
	RxSum float64 `json:"rx_sum"`
	TxSum float64 `json:"tx_sum"`
}

type PeerStats struct {
	PublicKey     string  `json:"public_key"`
	Alias         string  `json:"alias"`
	TotalRx       int64   `json:"total_rx"`
	TotalTx       int64   `json:"total_tx"`
	HealthScore   float64 `json:"health_score"`   // 0-100
	UptimePercent float64 `json:"uptime_percent"` // 0-100
	LastSeenTime  int64   `json:"last_seen_time"`
}

type AdvancedReport struct {
	Anomalies     []AnomalyEvent  `json:"anomalies"`
	ChurnRisks    []ChurnRisk     `json:"churn_risks"`
	OptimalTime   OptimalTime     `json:"optimal_time"`
	HourlyProfile []HourlyTraffic `json:"hourly_profile"`
	GlobalHeat    [][]float64     `json:"global_heatmap"` // 7x24 grid
	Peers         []PeerStats     `json:"peers"`
}

// ================= 1. 异常检测 (Anomaly Detection) =================

func (ae *AnalysisEngine) DetectAnomalies() ([]AnomalyEvent, error) {
	var anomalies []AnomalyEvent

	// 从内存基线缓存获取（替代 Redis）
	baselines := baselineCache.Get()

	if len(baselines) == 0 {
		logger.Println("未找到 Peer 基线缓存，跳过异常检测")
		return anomalies, nil
	}

	// 获取过去 15 分钟的最新流量数据
	query := `
		SELECT peer_public_key, (rx_bytes + tx_bytes) / 1048576.0 AS total_mb
		FROM traffic_history 
		WHERE timestamp > ? 
		ORDER BY timestamp ASC`

	fifteenMinsAgo := time.Now().Add(-15 * time.Minute).Unix()
	rows, err := ae.db.Query(query, fifteenMinsAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 聚合每个 Peer 近 15 分钟的各个时间点流量
	recentTraffic := make(map[string][]float64)
	for rows.Next() {
		var pk string
		var totalMB float64
		if err := rows.Scan(&pk, &totalMB); err != nil {
			continue
		}
		recentTraffic[pk] = append(recentTraffic[pk], totalMB)
	}

	// 实时异常裁定
	for pk, history := range recentTraffic {
		if len(history) == 0 {
			continue
		}

		baseline, hasBaseline := baselines[pk]
		if !hasBaseline || baseline.StdDevMB == 0 {
			continue
		}

		currentTraffic := history[len(history)-1]
		const checkPoints = 3

		// 规则 1: 突发流量 (Z-Score > 3) 且 绝对值 > 50MB
		zScore := (currentTraffic - baseline.MeanMB) / baseline.StdDevMB
		if zScore > 3 && currentTraffic > 50 {
			anomalies = append(anomalies, AnomalyEvent{
				PublicKey: pk,
				Type:      "traffic_spike",
				Severity:  "high",
				Message:   "检测到异常流量突发 (Z-Score > 3)",
				Time:      time.Now(),
			})
		} else if len(history) >= checkPoints {
			// 规则 2：持续高负载 (> 500MB)
			isHighLoad := true
			for i := 0; i < checkPoints; i++ {
				if history[len(history)-1-i] < 500 {
					isHighLoad = false
					break
				}
			}
			if isHighLoad {
				anomalies = append(anomalies, AnomalyEvent{
					PublicKey: pk,
					Type:      "network_abuse",
					Severity:  "medium",
					Message:   "持续高负载运行",
					Time:      time.Now(),
				})
			}
		}
	}

	return anomalies, nil
}

// ================= 2. 客户流失预测 (Churn Prediction) =================

func (ae *AnalysisEngine) PredictChurn() ([]ChurnRisk, error) {
	// 获取过去 30 天的每日汇总流量（SQLite 兼容语法）
	query := `
		SELECT peer_public_key, 
		       (timestamp / 86400) * 86400 as day_ts,
			   SUM(rx_bytes + tx_bytes) as daily_total
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY peer_public_key, day_ts
		ORDER BY day_ts ASC`

	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, thirtyDaysAgo)
	if err != nil {
		// 原始表可能已被降采样清理，尝试从聚合表查询
		return ae.predictChurnFromHourly()
	}
	defer rows.Close()

	return ae.processChurnRows(rows)
}

// predictChurnFromHourly 从小时聚合表计算流失风险（降采样后的备用路径）
func (ae *AnalysisEngine) predictChurnFromHourly() ([]ChurnRisk, error) {
	query := `
		SELECT peer_key, 
		       (hour_ts / 86400) * 86400 as day_ts,
			   SUM(total_rx + total_tx) as daily_total
		FROM traffic_hourly
		WHERE hour_ts > ?
		GROUP BY peer_key, day_ts
		ORDER BY day_ts ASC`

	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, thirtyDaysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ae.processChurnRows(rows)
}

// processChurnRows 通用流失风险处理逻辑
func (ae *AnalysisEngine) processChurnRows(rows *sql.Rows) ([]ChurnRisk, error) {
	peerDaily := make(map[string]map[int64]float64)
	allPeers := make(map[string]bool)

	for rows.Next() {
		var pk string
		var ts int64
		var total int64
		if err := rows.Scan(&pk, &ts, &total); err != nil {
			continue
		}
		if _, ok := peerDaily[pk]; !ok {
			peerDaily[pk] = make(map[int64]float64)
		}
		peerDaily[pk][ts] = float64(total)
		allPeers[pk] = true
	}

	var risks []ChurnRisk
	now := time.Now().Unix()

	for pk := range allPeers {
		dailyData := peerDaily[pk]

		var lastActiveTs int64 = 0
		for ts := range dailyData {
			if ts > lastActiveTs {
				lastActiveTs = ts
			}
		}

		daysOffline := 0
		if lastActiveTs > 0 {
			daysOffline = int((now - lastActiveTs) / 86400)
		} else {
			daysOffline = 30
		}

		// 线性回归计算趋势斜率
		var x []float64
		var y []float64
		var startTs int64
		if len(dailyData) > 0 {
			startTs = now
			for ts := range dailyData {
				if ts < startTs {
					startTs = ts
				}
			}
		}

		for ts, vol := range dailyData {
			dayIdx := float64((ts - startTs) / 86400)
			x = append(x, dayIdx)
			y = append(y, vol)
		}

		slope := linearRegression(x, y)

		riskLevel := "low"
		riskScore := 0.0

		if daysOffline > 14 {
			riskLevel = "churned"
			riskScore = 100.0
		} else if daysOffline > 7 {
			riskLevel = "high"
			riskScore = 80.0
		} else if slope < -0.5 && daysOffline > 3 {
			riskLevel = "medium"
			riskScore = 60.0
		} else if slope < -1.0 {
			riskLevel = "medium"
			riskScore = 50.0
		}

		if riskScore > 0 {
			risks = append(risks, ChurnRisk{
				PublicKey:   pk,
				RiskScore:   riskScore,
				RiskLevel:   riskLevel,
				DaysOffline: daysOffline,
				TrendSlope:  slope,
			})
		}
	}

	sort.Slice(risks, func(i, j int) bool {
		return risks[i].RiskScore > risks[j].RiskScore
	})

	return risks, nil
}

func linearRegression(x, y []float64) float64 {
	n := float64(len(x))
	if n < 2 {
		return 0
	}

	var sumX, sumY, sumXY, sumXX float64
	for i := 0; i < len(x); i++ {
		sumX += x[i]
		sumY += y[i]
		sumXY += x[i] * y[i]
		sumXX += x[i] * x[i]
	}

	denominator := n*sumXX - sumX*sumX
	if denominator == 0 {
		return 0
	}
	return (n*sumXY - sumX*sumY) / denominator
}

// ================= 3. 最佳连接时间 & 全局热力图 =================

func (ae *AnalysisEngine) RefinedAnalysis() (OptimalTime, [][]float64, []HourlyTraffic, error) {
	// SQLite 兼容语法：使用 strftime 替代 MySQL 的 HOUR/DAYOFWEEK
	query := `
		SELECT 
			CAST(strftime('%H', timestamp, 'unixepoch', 'localtime') AS INTEGER) as hour_of_day,
			CAST(strftime('%w', timestamp, 'unixepoch', 'localtime') AS INTEGER) as day_of_week, 
			AVG(rx_rate) as avg_rx,
			AVG(tx_rate) as avg_tx
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY day_of_week, hour_of_day`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		// 原始表可能已降采样，尝试从聚合表查询
		return ae.refinedAnalysisFromHourly()
	}
	defer rows.Close()

	return ae.processRefinedRows(rows)
}

// refinedAnalysisFromHourly 从小时聚合表执行时段分析
func (ae *AnalysisEngine) refinedAnalysisFromHourly() (OptimalTime, [][]float64, []HourlyTraffic, error) {
	query := `
		SELECT 
			CAST(strftime('%H', hour_ts, 'unixepoch', 'localtime') AS INTEGER) as hour_of_day,
			CAST(strftime('%w', hour_ts, 'unixepoch', 'localtime') AS INTEGER) as day_of_week, 
			AVG(avg_rx_rate) as avg_rx,
			AVG(avg_tx_rate) as avg_tx
		FROM traffic_hourly
		WHERE hour_ts > ?
		GROUP BY day_of_week, hour_of_day`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		return OptimalTime{}, nil, nil, err
	}
	defer rows.Close()

	return ae.processRefinedRows(rows)
}

// processRefinedRows 通用时段分析处理
func (ae *AnalysisEngine) processRefinedRows(rows *sql.Rows) (OptimalTime, [][]float64, []HourlyTraffic, error) {
	// 7x24 Heatmap
	heatmap := make([][]float64, 7)
	for i := range heatmap {
		heatmap[i] = make([]float64, 24)
	}

	hourlyRxSum := make([]float64, 24)
	hourlyTxSum := make([]float64, 24)
	hourlyCounts := make([]int, 24)

	for rows.Next() {
		var h, d int
		var rx, tx float64
		if err := rows.Scan(&h, &d, &rx, &tx); err != nil {
			continue
		}

		// SQLite strftime('%w') 返回 0=Sunday，与 MySQL DAYOFWEEK 不同
		// 统一为 0-6 索引
		if d >= 0 && d < 7 && h >= 0 && h < 24 {
			totalRate := rx + tx
			heatmap[d][h] = totalRate

			hourlyRxSum[h] += rx
			hourlyTxSum[h] += tx
			hourlyCounts[h]++
		}
	}

	var hourlyProfile []HourlyTraffic
	hourlyTotalAvg := make([]float64, 24)

	for i := 0; i < 24; i++ {
		count := float64(hourlyCounts[i])
		if count == 0 {
			count = 1
		}
		rxAvg := hourlyRxSum[i] / count
		txAvg := hourlyTxSum[i] / count
		hourlyProfile = append(hourlyProfile, HourlyTraffic{
			Hour:  i,
			RxSum: rxAvg,
			TxSum: txAvg,
		})
		hourlyTotalAvg[i] = rxAvg + txAvg
	}

	// 找最低负载的 3 小时窗口
	minTraffic := math.MaxFloat64
	bestHour := 0

	for i := 0; i < 24; i++ {
		sum := 0.0
		for j := 0; j < 3; j++ {
			idx := (i + j) % 24
			sum += hourlyTotalAvg[idx]
		}
		if sum < minTraffic {
			minTraffic = sum
			bestHour = i
		}
	}

	optimalLoad := minTraffic / 3

	return OptimalTime{
		StartHour:   bestHour,
		EndHour:     (bestHour + 3) % 24,
		AvgLoadMbps: optimalLoad,
	}, heatmap, hourlyProfile, nil
}

// ================= 4. Peer 统计分析 =================

func (ae *AnalysisEngine) AnalyzePeers() ([]PeerStats, error) {
	if aliasCache.NeedsRefresh() {
		aliasCache.Refresh(context.Background())
	}

	// SQLite 兼容查询
	query := `
		SELECT 
			peer_public_key,
			SUM(rx_rate) as dim_rx_rate,
			SUM(tx_rate) as dim_tx_rate,
			COUNT(*) as total_records,
			SUM(is_online) as online_records,
			MAX(timestamp) as last_seen
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY peer_public_key`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		// 原始表可能已降采样，尝试从聚合表查询
		return ae.analyzePeersFromHourly()
	}
	defer rows.Close()

	var peerStats []PeerStats
	hasData := false

	for rows.Next() {
		hasData = true
		var pk string
		var dimRxRate, dimTxRate float64
		var totalRecords, onlineRecords int
		var lastSeen int64

		if err := rows.Scan(&pk, &dimRxRate, &dimTxRate, &totalRecords, &onlineRecords, &lastSeen); err != nil {
			continue
		}

		// 流量估算
		const WindowSec = 5.0 // 与 CollectInterval 匹配（改为 5 秒）
		totalRx := int64(dimRxRate * WindowSec * 1000000 / 8)
		totalTx := int64(dimTxRate * WindowSec * 1000000 / 8)

		// 从内存状态缓存获取实时 last_seen
		if state, ok := peerStateCache.Get(pk); ok {
			if state.LastSeen > lastSeen {
				lastSeen = state.LastSeen
			}
		}

		healthScore := calculateHealthScore(onlineRecords, totalRecords, lastSeen)

		uptimePercent := 0.0
		if totalRecords > 0 {
			uptimePercent = (float64(onlineRecords) / float64(totalRecords)) * 100
		}

		alias, _ := aliasCache.Get(pk)

		peerStats = append(peerStats, PeerStats{
			PublicKey:     pk,
			Alias:         alias,
			TotalRx:       totalRx,
			TotalTx:       totalTx,
			HealthScore:   healthScore,
			UptimePercent: uptimePercent,
			LastSeenTime:  lastSeen,
		})
	}

	// 如果原始表无数据（已降采样），从聚合表补充
	if !hasData {
		return ae.analyzePeersFromHourly()
	}

	sort.Slice(peerStats, func(i, j int) bool {
		return (peerStats[i].TotalRx + peerStats[i].TotalTx) > (peerStats[j].TotalRx + peerStats[j].TotalTx)
	})

	return peerStats, nil
}

// analyzePeersFromHourly 从小时聚合表分析 Peer 统计（降采样后的备用路径）
func (ae *AnalysisEngine) analyzePeersFromHourly() ([]PeerStats, error) {
	query := `
		SELECT 
			peer_key,
			SUM(total_rx) as sum_rx,
			SUM(total_tx) as sum_tx,
			SUM(sample_count) as total_records,
			AVG(online_pct) as avg_online,
			MAX(hour_ts) as last_seen
		FROM traffic_hourly
		WHERE hour_ts > ?
		GROUP BY peer_key`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peerStats []PeerStats

	for rows.Next() {
		var pk string
		var totalRx, totalTx, totalRecords int64
		var avgOnline float64
		var lastSeen int64

		if err := rows.Scan(&pk, &totalRx, &totalTx, &totalRecords, &avgOnline, &lastSeen); err != nil {
			continue
		}

		healthScore := calculateHealthScore(int(float64(totalRecords)*avgOnline/100), int(totalRecords), lastSeen)

		alias, _ := aliasCache.Get(pk)

		peerStats = append(peerStats, PeerStats{
			PublicKey:     pk,
			Alias:         alias,
			TotalRx:       totalRx,
			TotalTx:       totalTx,
			HealthScore:   healthScore,
			UptimePercent: avgOnline,
			LastSeenTime:  lastSeen,
		})
	}

	sort.Slice(peerStats, func(i, j int) bool {
		return (peerStats[i].TotalRx + peerStats[i].TotalTx) > (peerStats[j].TotalRx + peerStats[j].TotalTx)
	})

	return peerStats, nil
}

func calculateHealthScore(onlineRecords, totalRecords int, lastSeen int64) float64 {
	if totalRecords == 0 {
		return 0
	}

	baseScore := (float64(onlineRecords) / float64(totalRecords)) * 100

	penalty := 0.0
	if lastSeen < time.Now().Add(-24*time.Hour).Unix() {
		penalty = 30.0
	}

	score := baseScore - penalty

	if score < 0 {
		score = 0
	}

	return math.Round(score)
}

func (ae *AnalysisEngine) GetAdvancedReport() (AdvancedReport, error) {
	// 从内存 TTL 缓存获取（替代 Redis）
	if report, ok := advancedReportCache.Get(); ok {
		metrics.IncCacheHits()
		return report, nil
	}
	metrics.IncCacheMisses()

	// 缓存未命中，执行查询
	anomalies, err := ae.DetectAnomalies()
	if err != nil {
		return AdvancedReport{}, err
	}

	churns, err := ae.PredictChurn()
	if err != nil {
		return AdvancedReport{}, err
	}

	optTime, heatmap, hourlyProfile, err := ae.RefinedAnalysis()
	if err != nil {
		return AdvancedReport{}, err
	}

	peerStats, err := ae.AnalyzePeers()
	if err != nil {
		return AdvancedReport{}, err
	}

	report := AdvancedReport{
		Anomalies:     anomalies,
		ChurnRisks:    churns,
		OptimalTime:   optTime,
		GlobalHeat:    heatmap,
		HourlyProfile: hourlyProfile,
		Peers:         peerStats,
	}

	return report, nil
}
