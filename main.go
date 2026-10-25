package main

import (
	"context"
	"embed"
	"sync"
)

//go:embed index.html
var indexHtml string

//go:embed static/*
var staticFS embed.FS

// main 是程序入口：解析配置、初始化各组件、启动所有后台服务、监听 HTTP 请求
func main() {
	// 初始化日志系统
	initLogger()

	// 解析命令行参数与环境变量
	parseFlags()

	// 初始化 WireGuard 执行抽象层（安全红线：支持 Mock 沙盒隔离与宿主机防护）
	InitExecutor()

	// 初始化各组件
	initGeoIP()
	initMemoryEngine()
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
