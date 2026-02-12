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

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			precomputeAnalysisReport(ctx)
		}
	}
}

func precomputeAnalysisReport(ctx context.Context) {
	logger.Println("开始预计算分析报告...")

	report, err := analysisEngine.GetAdvancedReport()
	if err != nil {
		logger.Printf("预计算分析报告失败: %v", err)
		return
	}

	// 写入缓存（2 分钟 TTL，比定时任务间隔多 1 分钟，避免空窗期）
	if jsonBytes, err := json.Marshal(report); err == nil {
		cacheKey := "wg:cache:advanced_report"
		if err := rdb.Set(ctx, cacheKey, jsonBytes, 2*time.Minute).Err(); err != nil {
			logger.Printf("写入预计算缓存失败: %v", err)
		} else {
			logger.Printf("预计算分析报告完成，缓存已更新")
		}
	} else {
		logger.Printf("序列化分析报告失败: %v", err)
	}
}
