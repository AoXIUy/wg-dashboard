package main

import (
	"context"
	"encoding/json"
	"time"
)

// ================= 分析报告预计算定时任务 =================

// 全局缓存最新的重负载分析结果，供短周期生成最终报告时合并使用
var (
	latestHeavyReport *AdvancedReport
)

func startAnalysisPrecompute(ctx context.Context) {
	if !redisEnabled || analysisEngine == nil {
		logger.Println("分析预计算器已跳过（Redis 未启用或分析引擎未初始化）")
		return
	}

	logger.Println("分析预计算器已启动")
	defer logger.Println("分析预计算器已停止")

	// 启动时立即执行一次长短周期的重计算
	precomputeHeavyTasks(ctx)
	precomputeAnalysisReport(ctx)
	precomputePeerBaselines(ctx) // 立即计算一次基线

	// 分析报告 Ticker (轻量级/最近15分钟) - 每分钟
	tickerLight := time.NewTicker(1 * time.Minute)
	defer tickerLight.Stop()

	// 深度分析 Ticker (重负载/过去7天-30天) - 每小时
	tickerHeavy := time.NewTicker(1 * time.Hour)
	defer tickerHeavy.Stop()

	// 基线计算 Ticker (每小时)
	tickerBaseline := time.NewTicker(1 * time.Hour)
	defer tickerBaseline.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerLight.C:
			precomputeAnalysisReport(ctx)
		case <-tickerHeavy.C:
			precomputeHeavyTasks(ctx)
		case <-tickerBaseline.C:
			precomputePeerBaselines(ctx)
		}
	}
}

// precomputeHeavyTasks 计算耗时长、数据跨度大的分析指标（如30天流失、7天热力图等），并将结果存入内存以便拼装
func precomputeHeavyTasks(ctx context.Context) {
	logger.Println("开始执行重负载深度分析计算...")

	churns, err := analysisEngine.PredictChurn()
	if err != nil {
		logger.Printf("深度分析 - 预计算流失预测失败: %v", err)
		churns = []ChurnRisk{}
	}

	optTime, heatmap, hourlyProfile, err := analysisEngine.RefinedAnalysis()
	if err != nil {
		logger.Printf("深度分析 - 预计算时段分析失败: %v", err)
	}

	peerStats, err := analysisEngine.AnalyzePeers()
	if err != nil {
		logger.Printf("深度分析 - 预计算 Peer 分析失败: %v", err)
		peerStats = []PeerStats{}
	}

	latestHeavyReport = &AdvancedReport{
		ChurnRisks:    churns,
		OptimalTime:   optTime,
		GlobalHeat:    heatmap,
		HourlyProfile: hourlyProfile,
		Peers:         peerStats,
	}
	logger.Println("重负载深度分析计算完成并更新内存副本")
}

// precomputeAnalysisReport 每分钟执行轻量级实时计算（如 15分钟异常检测），并将其与内存中的深度分析报告拼装后写入缓存
func precomputeAnalysisReport(ctx context.Context) {
	logger.Println("开始生成综合分析报告(轻量级计算+重负载合并)...")

	// 轻量级：近 15 分钟异常检测
	anomalies, err := analysisEngine.DetectAnomalies()
	if err != nil {
		logger.Printf("预计算异常检测失败: %v", err)
		anomalies = []AnomalyEvent{}
	}

	// 初始化一个空壳子，并把最新鲜的 anomalies 塞进去
	report := AdvancedReport{
		Anomalies: anomalies,
	}

	// 如果有深度分析结果的备份，直接挂载进去
	if latestHeavyReport != nil {
		report.ChurnRisks = latestHeavyReport.ChurnRisks
		report.OptimalTime = latestHeavyReport.OptimalTime
		report.GlobalHeat = latestHeavyReport.GlobalHeat
		report.HourlyProfile = latestHeavyReport.HourlyProfile
		report.Peers = latestHeavyReport.Peers
	} else {
		logger.Println("警告：深度分析结果尚未就绪，综合报告将只有异常检测告警")
		report.ChurnRisks = []ChurnRisk{}
		report.Peers = []PeerStats{}
	}

	// 写入缓存（2 分钟 TTL，比定时任务间隔多 1 分钟，避免空窗期）
	if jsonBytes, err := json.Marshal(report); err == nil {
		cacheKey := "wg:cache:advanced_report"
		if err := rdb.Set(ctx, cacheKey, jsonBytes, 2*time.Minute).Err(); err != nil {
			logger.Printf("写入综合分析报告缓存失败: %v", err)
		} else {
			logger.Printf("综合分析报告完成并回写缓存（peers=%d, anomalies=%d）",
				len(report.Peers), len(anomalies))
			// 通知前端刷新分析数据
			select {
			case sseBroker.Message <- `{"type":"analysis_updated"}`:
			default:
			}
		}
	} else {
		logger.Printf("序列化分析报告失败: %v", err)
	}
}

// 供 redis 缓存的 Peer 基线结构，保证 analysis.go 也能复用此定义（或各自定义相同的结构）
type PeerBaseline struct {
	MeanMB   float64 `json:"mean_mb"`
	StdDevMB float64 `json:"stddev_mb"`
}

// precomputePeerBaselines 计算过去 24小时 所有 Peer 的流量均值与方差（基线）并存入 Redis
func precomputePeerBaselines(ctx context.Context) {
	logger.Println("开始预计算 Peer 流量基线...")

	// 仅对过去 1 天的数据进行聚合，利用 MySQL 内置函数计算
	query := `
		SELECT 
			peer_public_key,
			AVG((rx_bytes + tx_bytes) / 1048576) AS mean_mb,
			STDDEV((rx_bytes + tx_bytes) / 1048576) AS stddev_mb
		FROM traffic_history
		WHERE timestamp > UNIX_TIMESTAMP(NOW() - INTERVAL 1 DAY)
		GROUP BY peer_public_key`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Printf("预计算 Peer 基线查询失败: %v", err)
		return
	}
	defer rows.Close()

	baselines := make(map[string]PeerBaseline)

	for rows.Next() {
		var pk string
		var mean, stddev float64
		if err := rows.Scan(&pk, &mean, &stddev); err != nil {
			logger.Printf("扫描 Peer 基线行失败: %v", err)
			continue
		}
		baselines[pk] = PeerBaseline{
			MeanMB:   mean,
			StdDevMB: stddev,
		}
	}

	if len(baselines) == 0 {
		logger.Println("未找到任何符合条件的 Peer 基线数据跳过更新")
		return
	}

	// 序列化后写入 Redis
	jsonBytes, err := json.Marshal(baselines)
	if err != nil {
		logger.Printf("序列化 Peer 基线数据失败: %v", err)
		return
	}

	cacheKey := "wg:cache:peer_baseline"
	// TTL 设为 2 小时，容忍一次 Ticker 丢失
	if err := rdb.Set(ctx, cacheKey, jsonBytes, 2*time.Hour).Err(); err != nil {
		logger.Printf("写入 Peer 基线缓存失败: %v", err)
	} else {
		logger.Printf("预计算 Peer 流量基线完成，缓存已更新 (更新了 %d 个 Peer)", len(baselines))
	}
}
