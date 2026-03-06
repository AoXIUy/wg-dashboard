package main

import (
	"context"
	"encoding/json"
	"time"
)

// ================= 分析报告预计算定时任务 =================

func startAnalysisPrecompute(ctx context.Context) {
	if !redisEnabled || analysisEngine == nil {
		logger.Println("分析预计算器已跳过（Redis 未启用或分析引擎未初始化）")
		return
	}

	logger.Println("分析预计算器已启动")
	defer logger.Println("分析预计算器已停止")

	// 启动时立即执行一次预计算
	precomputeAnalysisReport(ctx)
	precomputePeerBaselines(ctx) // 立即计算一次基线

	// 分析报告 Ticker (每分钟)
	tickerReport := time.NewTicker(1 * time.Minute)
	defer tickerReport.Stop()

	// 基线计算 Ticker (每小时)
	tickerBaseline := time.NewTicker(1 * time.Hour)
	defer tickerBaseline.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerReport.C:
			precomputeAnalysisReport(ctx)
		case <-tickerBaseline.C:
			precomputePeerBaselines(ctx)
		}
	}
}

func precomputeAnalysisReport(ctx context.Context) {
	logger.Println("开始预计算分析报告...")

	// 【死锁修复】不再调用 GetAdvancedReport()，因为它会先读 Redis 缓存。
	// 若缓存命中旧数据，将导致"读旧缓存 → 写旧缓存"的自我强化死循环，缓存永远无法更新。
	// 解决方案：直接调用各分析子方法，完全绕过缓存层，确保每次都从数据库计算最新数据。
	anomalies, err := analysisEngine.DetectAnomalies()
	if err != nil {
		logger.Printf("预计算异常检测失败: %v", err)
		anomalies = []AnomalyEvent{}
	}

	churns, err := analysisEngine.PredictChurn()
	if err != nil {
		logger.Printf("预计算流失预测失败: %v", err)
		churns = []ChurnRisk{}
	}

	optTime, heatmap, hourlyProfile, err := analysisEngine.RefinedAnalysis()
	if err != nil {
		logger.Printf("预计算时段分析失败: %v", err)
	}

	peerStats, err := analysisEngine.AnalyzePeers()
	if err != nil {
		logger.Printf("预计算 Peer 分析失败: %v", err)
		peerStats = []PeerStats{}
	}

	report := AdvancedReport{
		Anomalies:     anomalies,
		ChurnRisks:    churns,
		OptimalTime:   optTime,
		GlobalHeat:    heatmap,
		HourlyProfile: hourlyProfile,
		Peers:         peerStats,
	}

	// 写入缓存（2 分钟 TTL，比定时任务间隔多 1 分钟，避免空窗期）
	if jsonBytes, err := json.Marshal(report); err == nil {
		cacheKey := "wg:cache:advanced_report"
		if err := rdb.Set(ctx, cacheKey, jsonBytes, 2*time.Minute).Err(); err != nil {
			logger.Printf("写入预计算缓存失败: %v", err)
		} else {
			logger.Printf("预计算分析报告完成，缓存已更新（peers=%d, anomalies=%d）",
				len(peerStats), len(anomalies))
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
