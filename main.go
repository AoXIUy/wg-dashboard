package main

import (
	"context"
	_ "embed"
	"os"
	"sync"
)

//go:embed index.html
var indexHtml string

// main 是程序入口：解析配置、初始化各组件、启动所有后台服务、监听 HTTP 请求
func main() {
	// 初始化日志系统
	initLogger()

	// 解析命令行参数与环境变量
	parseFlags()

	if os.Geteuid() != 0 {
		logger.Println("警告: 未以 Root 权限运行，无法管理 WireGuard 配置，仅能监控。")
	}

	// 初始化各组件
	initGeoIP()
	initRedis()
	initComponents()

	if err := initDB(); err != nil {
		logger.Fatalf("数据库初始化失败: %v", err)
	}
	defer closeDB()

	// 加载别名缓存
	if err := aliasCache.Refresh(context.Background()); err != nil {
		logger.Printf("初始别名缓存加载失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rawChan := make(chan RawSnapshot, 20)
	var wg sync.WaitGroup

	// 启动所有后台 goroutine
	startBackgroundServices(ctx, &wg, rawChan)

	// 启动 HTTP 服务器
	srv := startHTTPServer()

	// 等待退出信号并优雅关闭
	gracefulShutdown(srv, cancel, &wg)
}