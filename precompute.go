package main

import (
	"context"
	"math"
	"time"
)

// ================= 分析报告预计算定时任务 =================

// 全局缓存最新的重负载分析结果，供短周期生成最终报告时合并使用
var (
	latestHeavyReport *AdvancedReport
)

func startAnalysisPrecompute(ctx context.Context) {
	if analysisEngine == nil {
		logger.Println("分析预计算器已跳过（分析引擎未初始化）")
		return
	}

	logger.Println("分析预计算器已启动，将在 30 秒后开始首次计算...")
	defer logger.Println("分析预计算器已停止")

	// 延迟 30 秒后才执行第一次计算，让系统先稳定
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	precomputeHeavyTasks(ctx)
	precomputeAnalysisReport(ctx)
	precomputePeerBaselines(ctx)

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

// precomputeHeavyTasks 计算耗时长、数据跨度大的分析指标
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

// precomputeAnalysisReport 每分钟执行轻量级实时计算并将其与内存中的深度分析报告拼装后写入缓存
func precomputeAnalysisReport(ctx context.Context) {
	logger.Println("开始生成综合分析报告(轻量级计算+重负载合并)...")

	// 轻量级：近 15 分钟异常检测
	anomalies, err := analysisEngine.DetectAnomalies()
	if err != nil {
		logger.Printf("预计算异常检测失败: %v", err)
		anomalies = []AnomalyEvent{}
	}

	report := AdvancedReport{
		Anomalies: anomalies,
	}

	// 如果有深度分析结果的备份，直接挂载
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

	// 写入内存 TTL 缓存（替代 Redis SET ... EX 120）
	advancedReportCache.Set(report)
	logger.Printf("综合分析报告完成并写入内存缓存（peers=%d, anomalies=%d）",
		len(report.Peers), len(anomalies))

	// 通知前端刷新分析数据
	select {
	case sseBroker.Message <- `{"type":"analysis_updated"}`:
	default:
	}
}

// PeerBaseline 供缓存的 Peer 基线结构
type PeerBaseline struct {
	MeanMB   float64 `json:"mean_mb"`
	StdDevMB float64 `json:"stddev_mb"`
}

// precomputePeerBaselines 计算过去 24小时所有 Peer 的流量均值与方差（基线）
func precomputePeerBaselines(ctx context.Context) {
	logger.Println("开始预计算 Peer 流量基线...")

	oneDayAgo := time.Now().Add(-24 * time.Hour).Unix()

	// 使用方差的数学公式 AVG(X^2) - AVG(X)^2 一次性计算所有 Peer 的均值和方差，规避 N+1 查询
	query := `
		SELECT 
			peer_public_key,
			AVG(total_mb) AS mean_mb,
			AVG(total_mb * total_mb) - AVG(total_mb) * AVG(total_mb) AS variance
		FROM (
			SELECT peer_public_key, (rx_bytes + tx_bytes) / 1048576.0 AS total_mb
			FROM traffic_history 
			WHERE timestamp > ?
		) GROUP BY peer_public_key`

	rows, err := db.QueryContext(ctx, query, oneDayAgo)
	if err != nil {
		logger.Printf("预计算 Peer 基线查询失败: %v", err)
		return
	}
	defer rows.Close()

	baselines := make(map[string]PeerBaseline)
	for rows.Next() {
		var pk string
		var mean, variance float64
		if err := rows.Scan(&pk, &mean, &variance); err != nil {
			continue
		}

		stddev := 0.0
		if variance > 0 {
			stddev = math.Sqrt(variance)
		}

		baselines[pk] = PeerBaseline{
			MeanMB:   mean,
			StdDevMB: stddev,
		}
	}

	if len(baselines) == 0 {
		logger.Println("未找到任何符合条件的 Peer 基线数据，跳过更新")
		return
	}

	// 写入内存基线缓存（替代 Redis SET wg:cache:peer_baseline）
	baselineCache.Set(baselines)
	logger.Printf("预计算 Peer 流量基线完成，内存缓存已更新 (更新了 %d 个 Peer)", len(baselines))
}
