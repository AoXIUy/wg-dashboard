package main

import (
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
	Type      string    `json:"type"` // "traffic_spike", "network_abuse"
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
	// 获取过去 24 小时的流量数据用于建立基准
	query := `
		SELECT peer_public_key, rx_bytes, tx_bytes, timestamp 
		FROM traffic_history 
		WHERE timestamp > ? 
		ORDER BY timestamp ASC`
	
	yesterday := time.Now().Add(-24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, yesterday)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 聚合每个 Peer 的流量数据
	peerTraffic := make(map[string][]float64) // 存储每个时间点的总流量 (Rx+Tx)
	
	for rows.Next() {
		var pk string
		var rx, tx int64
		var ts int64
		if err := rows.Scan(&pk, &rx, &tx, &ts); err != nil {
			continue
		}
		totalMB := float64(rx+tx) / 1024 / 1024
		peerTraffic[pk] = append(peerTraffic[pk], totalMB)
	}

	var anomalies []AnomalyEvent

	for pk, history := range peerTraffic {
		if len(history) < 10 {
			continue // 数据太少，无法分析
		}

		// 计算均值和标准差
		mean, stdDev := calculateStats(history)

		// 获取最近的一个流量点 (假设最后一条记录是最近的)
		currentTraffic := history[len(history)-1]

		// 规则 1: 突发流量 (Z-Score > 3) 且 绝对值 > 50MB (避免小流量误报)
		if stdDev > 0 {
			zScore := (currentTraffic - mean) / stdDev
			if zScore > 3 && currentTraffic > 50 {
				anomalies = append(anomalies, AnomalyEvent{
					PublicKey: pk,
					Type:      "traffic_spike",
					Severity:  "high",
					Message:   "检测到异常流量突发 (Z-Score > 3)",
					Time:      time.Now(),
				})
			}
		}

		// 规则 2: 持续高负载 (简单的阈值判断，这里简化为检查最近几个点)
		// 实际生产中可能需要对比该用户的带宽限额，由于不知限额，暂定 > 500MB 为高负载
		isHighLoad := true
		checkPoints := 3
		if len(history) >= checkPoints {
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

func calculateStats(data []float64) (mean, stdDev float64) {
	if len(data) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range data {
		sum += v
	}
	mean = sum / float64(len(data))

	var varianceSum float64
	for _, v := range data {
		varianceSum += math.Pow(v-mean, 2)
	}
	variance := varianceSum / float64(len(data))
	stdDev = math.Sqrt(variance)
	return
}

// ================= 2. 客户流失预测 (Churn Prediction) =================

func (ae *AnalysisEngine) PredictChurn() ([]ChurnRisk, error) {
	// 获取过去 30 天的每日汇总流量
	query := `
		SELECT peer_public_key, 
		       FLOOR(timestamp / 86400) * 86400 as day_ts,
			   SUM(rx_bytes + tx_bytes) as daily_total
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY peer_public_key, day_ts
		ORDER BY day_ts ASC`

	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, thirtyDaysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 组织数据: Peer -> [DayIndex]Traffic
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
		
		// 1. 计算最后一次活跃距离现在的天数
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
			daysOffline = 30 // 既然查出来了但没数据(其实group by不会出现这种情况，防御性编程)，或者30天内无数据
		}

		// 2. 线性回归计算趋势斜率
		// 将时间戳归一化为 0, 1, 2... (第几天)
		var x []float64
		var y []float64
		var startTs int64
		if len(dailyData) > 0 {
			// 找到最早的一天
			startTs = now // init
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

		// 3. 判定风险等级
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
		} else if slope < -1.0 { // 流量急剧下降
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

	// 按风险分数排序
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

	// Slope (m) = (n*sumXY - sumX*sumY) / (n*sumXX - sumX*sumX)
	denominator := n*sumXX - sumX*sumX
	if denominator == 0 {
		return 0
	}
	return (n*sumXY - sumX*sumY) / denominator
}

// ================= 3. 最佳连接时间 & 全局热力图 (Optimal Time & Heatmap) =================



func (ae *AnalysisEngine) RefinedAnalysis() (OptimalTime, [][]float64, []HourlyTraffic, error) {
	// 使用 rx_rate 和 tx_rate，更直接反映带宽压力
	query := `
		SELECT 
			HOUR(FROM_UNIXTIME(timestamp)) as hour_of_day,
			DAYOFWEEK(FROM_UNIXTIME(timestamp)) as day_of_week, 
			AVG(rx_rate) as avg_rx,
			AVG(tx_rate) as avg_tx
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY day_of_week, hour_of_day`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		return OptimalTime{}, nil, nil, err
	}
	defer rows.Close()

	// 7x24 Heatmap (Combined Load)
	heatmap := make([][]float64, 7)
	for i := range heatmap {
		heatmap[i] = make([]float64, 24)
	}
	
	// Hourly Profile (24h) - Accumulators
	hourlyRxSum := make([]float64, 24)
	hourlyTxSum := make([]float64, 24)
	hourlyCounts := make([]int, 24) // How many days of data for this hour

	for rows.Next() {
		var h, d int
		var rx, tx float64 // Mbps
		if err := rows.Scan(&h, &d, &rx, &tx); err != nil {
			continue
		}
		
		dayIdx := d - 1
		if dayIdx >= 0 && dayIdx < 7 && h >= 0 && h < 24 {
			totalRate := rx + tx
			heatmap[dayIdx][h] = totalRate
			
			hourlyRxSum[h] += rx
			hourlyTxSum[h] += tx
			hourlyCounts[h]++
		}
	}

	// Build Hourly Profile
	var hourlyProfile []HourlyTraffic
	// Also calc total avg for Optimal Time
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

	// Calculate Optimal Time (Low traffic window)
	// Find the 3-hour window with lowest sum
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

	// Calculate average load during that window
	optimalLoad := minTraffic / 3

	return OptimalTime{
		StartHour:   bestHour,
		EndHour:     (bestHour + 3) % 24,
		AvgLoadMbps: optimalLoad,
	}, heatmap, hourlyProfile, nil
}

// ================= 4. Peer 统计分析 (Peer Statistics) =================

func (ae *AnalysisEngine) AnalyzePeers() ([]PeerStats, error) {
	// 查询过去 7 天的流量统计
	query := `
		SELECT 
			peer_public_key,
			SUM(rx_bytes) as total_rx,
			SUM(tx_bytes) as total_tx,
			COUNT(*) as total_records,
			SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) as online_records,
			MAX(timestamp) as last_seen
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY peer_public_key`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peerStats []PeerStats

	for rows.Next() {
		var pk string
		var totalRx, totalTx int64
		var totalRecords, onlineRecords int
		var lastSeen int64

		if err := rows.Scan(&pk, &totalRx, &totalTx, &totalRecords, &onlineRecords, &lastSeen); err != nil {
			continue
		}

		// 计算在线率
		uptimePercent := 0.0
		if totalRecords > 0 {
			uptimePercent = (float64(onlineRecords) / float64(totalRecords)) * 100
		}

		// 计算健康分
		healthScore := calculateHealthScore(uptimePercent, lastSeen, totalRx+totalTx)

		// 获取别名
		alias := ""
		aliasQuery := "SELECT alias FROM peer_aliases WHERE public_key = ?"
		ae.db.QueryRow(aliasQuery, pk).Scan(&alias)

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

	// 按流量排序（降序）
	sort.Slice(peerStats, func(i, j int) bool {
		return (peerStats[i].TotalRx + peerStats[i].TotalTx) > (peerStats[j].TotalRx + peerStats[j].TotalTx)
	})

	return peerStats, nil
}

func calculateHealthScore(uptimePercent float64, lastSeen int64, totalTraffic int64) float64 {
	// 基础分：在线率占 60%
	score := uptimePercent * 0.6

	// 近期活跃加成：最多 30 分
	now := time.Now().Unix()
	timeSinceLastSeen := now - lastSeen
	if timeSinceLastSeen < 3600 { // 1小时内
		score += 30
	} else if timeSinceLastSeen < 86400 { // 24小时内
		score += 20
	} else if timeSinceLastSeen < 604800 { // 7天内
		score += 10
	}

	// 流量活跃度加成：最多 10 分
	if totalTraffic > 10*1024*1024*1024 { // 10GB+
		score += 10
	} else if totalTraffic > 1024*1024*1024 { // 1GB+
		score += 5
	} else if totalTraffic > 100*1024*1024 { // 100MB+
		score += 2
	}

	// 限制在 0-100 范围内
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return math.Round(score)
}

func (ae *AnalysisEngine) GetAdvancedReport() (AdvancedReport, error) {
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

	return AdvancedReport{
		Anomalies:     anomalies,
		ChurnRisks:    churns,
		OptimalTime:   optTime,
		GlobalHeat:    heatmap,
		HourlyProfile: hourlyProfile,
		Peers:         peerStats,
	}, nil
}
