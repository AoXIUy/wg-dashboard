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

type AdvancedReport struct {
	Anomalies    []AnomalyEvent `json:"anomalies"`
	ChurnRisks   []ChurnRisk    `json:"churn_risks"`
	OptimalTime  OptimalTime    `json:"optimal_time"`
	GlobalHeat   [][]float64    `json:"global_heatmap"` // 7x24 grid
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

func (ae *AnalysisEngine) AnalyzeGlobalTraffic() (OptimalTime, [][]float64, error) {
	// 获取过去 7 天的流量，按小时分组
	query := `
		SELECT 
			HOUR(FROM_UNIXTIME(timestamp)) as hour_of_day,
			DAYOFWEEK(FROM_UNIXTIME(timestamp)) as day_of_week, -- 1=Sun, 2=Mon...
			AVG(rx_bytes + tx_bytes) as avg_traffic
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY day_of_week, hour_of_day`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		return OptimalTime{}, nil, err
	}
	defer rows.Close()

	// 初始化 Heatmap: 7 days * 24 hours
	// 行: 星期 (0=Sun, 1=Mon...6=Sat) - 注意 MySQL DAYOFWEEK 是 1-7
	// 列: 小时 (0-23)
	heatmap := make([][]float64, 7)
	for i := range heatmap {
		heatmap[i] = make([]float64, 24)
	}

	// 此时也顺便计算每小时的全局平均流量，用于找Optimal Time
	hourlyTotal := make([]float64, 24)
	hourlyCount := make([]int, 24)

	for rows.Next() {
		var h, d int
		var avgBytes float64
		if err := rows.Scan(&h, &d, &avgBytes); err != nil {
			continue
		}
		
		// MySQL Day: 1=Sun, 2=Mon... 7=Sat
		// Go Struct: Let's map 0=Sun, 1=Mon...
		dayIdx := d - 1
		if dayIdx < 0 || dayIdx > 6 {
			continue
		}
		if h < 0 || h > 23 {
			continue
		}

		mbps := (avgBytes * 8) / 1000000 // Convert bytes to Mbps (average over collection interval is not quite rate, but bytes intensity)
		// 注意: traffic_history 存的是累积量还是增量？
		// 检查 main.go: traffic_history 存的是 rx_bytes, tx_bytes. 看起来是 snapshots.
		// 其实 ProcessedLog 里的 rx_rate/tx_rate 没存入库？ 
		// 查看 main.go 的 schema: rx_rate REAL, tx_rate REAL 都有.
		// 所以查询其实应该查 rx_rate + tx_rate 的平均值更准确.
		
		heatmap[dayIdx][h] = mbps
		
		hourlyTotal[h] += mbps
		hourlyCount[h]++
	}

	// 修正查询：因为 traffic_history 里有 rate 字段，我们重新写一个查 rate 的版本更稳
	// 但为了保持代码连贯，我们先假设上面的 avg_traffic 其实是想表达 rate。
	// 如果 traffic_history 主要是为了存流量快照，那 rx_bytes 是累积值吗？
	// 检查 main.go L658: rx_bytes BIGINT UNSIGNED NOT NULL.
	// 通常这种 Monitor 存的是 Counter。如果要算速率，得由 derivative 算出。
	// 但是 L660 也有 rx_rate REAL. 
	// 让我们改用 rx_rate + tx_rate.

	return ae.RefinedAnalysis()
}

func (ae *AnalysisEngine) RefinedAnalysis() (OptimalTime, [][]float64, error) {
	// 使用 rx_rate 和 tx_rate，更直接反映带宽压力
	query := `
		SELECT 
			HOUR(FROM_UNIXTIME(timestamp)) as hour_of_day,
			DAYOFWEEK(FROM_UNIXTIME(timestamp)) as day_of_week, 
			AVG(rx_rate + tx_rate) as avg_rate_mbps
		FROM traffic_history
		WHERE timestamp > ?
		GROUP BY day_of_week, hour_of_day`

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	rows, err := ae.db.Query(query, sevenDaysAgo)
	if err != nil {
		return OptimalTime{}, nil, err
	}
	defer rows.Close()

	heatmap := make([][]float64, 7)
	for i := range heatmap {
		heatmap[i] = make([]float64, 24)
	}
	
	hourlyAvg := make([]float64, 24)
	
	for rows.Next() {
		var h, d int
		var rate float64 // Mbps
		if err := rows.Scan(&h, &d, &rate); err != nil {
			continue
		}
		
		dayIdx := d - 1
		if dayIdx >= 0 && dayIdx < 7 && h >= 0 && h < 24 {
			// rate 在数据库是存的 float (main.go L87), 假设单位是 Mbps? 
			// Check main.go L57: MegabitsPerSecond = 1000000.0. 
			// Check main.go Processor logic (not fully visible but implied).
			// Assuming rate IS Mbps or similar.
			heatmap[dayIdx][h] = rate
			hourlyAvg[h] += rate
		}
	}

	// Calculate Optimal Time (Low traffic window)
	// Find the 3-hour window with lowest sum
	minTraffic := math.MaxFloat64
	bestHour := 0
	
	// Normalize hourlyAvg (divide by 7 days approx, or just use sum for comparison)
	// Cyclic check
	for i := 0; i < 24; i++ {
		sum := 0.0
		for j := 0; j < 3; j++ {
			idx := (i + j) % 24
			sum += hourlyAvg[idx]
		}
		if sum < minTraffic {
			minTraffic = sum
			bestHour = i
		}
	}

	// Calculate average load during that window
	optimalLoad := minTraffic / (3 * 7) // approx average

	return OptimalTime{
		StartHour:   bestHour,
		EndHour:     (bestHour + 3) % 24,
		AvgLoadMbps: optimalLoad,
	}, heatmap, nil
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

	optTime, heatmap, err := ae.RefinedAnalysis()
	if err != nil {
		return AdvancedReport{}, err
	}

	return AdvancedReport{
		Anomalies:   anomalies,
		ChurnRisks:  churns,
		OptimalTime: optTime,
		GlobalHeat:  heatmap,
	}, nil
}
