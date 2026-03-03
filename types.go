package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ================= 核心数据结构 =================

// RawSnapshot 原始 WireGuard 快照
type RawSnapshot struct {
	Timestamp time.Time
	Peers     []wgtypes.Peer
}

// ProcessedLog 经过速率计算后的记录，用于写入数据库
type ProcessedLog struct {
	Timestamp int64
	PublicKey string
	Endpoint  string
	RxBytes   int64
	TxBytes   int64
	RxRate    float64
	TxRate    float64
	IsOnline  bool
	Latency   string
}

// PeerData 返回给前端的 Peer 完整状态
type PeerData struct {
	PublicKey       string    `json:"public_key"`
	AllowedIPs      []string  `json:"allowed_ips"`
	Endpoint        string    `json:"endpoint"`
	LastHandshake   time.Time `json:"last_handshake"`
	LatestHandshake int64     `json:"latest_handshake"` // Unix 时间戳，用于前端拓扑图
	ReceiveBytes    int64     `json:"receive_bytes"`
	TransmitBytes   int64     `json:"transmit_bytes"`
	Alias           string    `json:"alias"`
	RxRate          float64   `json:"rx_rate"`
	TxRate          float64   `json:"tx_rate"`
	IsOnline        bool      `json:"is_online"`
	Latency         string    `json:"latency"`
	LastSeen        time.Time `json:"-"`             // 内部字段，不导出；前端使用 LastSeenTime
	LastSeenTime    int64     `json:"last_seen_time"` // Unix 时间戳，用于前端拓扑图
	Enabled         bool  `json:"enabled"`        // 客户端启用状态（默认 true）
}

// PeerState 采集器内部状态，用于计算速率增量
type PeerState struct {
	LastRx   int64
	LastTx   int64
	LastSeen time.Time
}

// SystemInfo 系统资源状态
type SystemInfo struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	CPUTemp    float64 `json:"cpu_temp"`
	Uptime     uint64  `json:"uptime"`
	HostName   string  `json:"hostname"`
	OS         string  `json:"os"`
}

// ================= 鉴权结构 =================

// LoginRequest 登录请求体
type LoginRequest struct {
	Password string `json:"password" binding:"required"`
}

// JwtClaims JWT 自定义载荷
type JwtClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

// ================= 管理结构 =================

// AddPeerRequest 新增 Peer 请求体
type AddPeerRequest struct {
	ConfigFile string `json:"config_file"`
	Name       string `json:"name"`
	AllowedIPs string `json:"allowed_ips"`
}

// ================= 分析结构 =================

// PeerAnalysis 单个 Peer 的分析摘要
type PeerAnalysis struct {
	PublicKey       string   `json:"public_key"`
	Alias           string   `json:"alias"`
	TotalRx         int64    `json:"total_rx"`
	TotalTx         int64    `json:"total_tx"`
	Uptime          float64  `json:"uptime_percent"`
	HealthScore     int      `json:"health_score"`
	LastSeenTime    int64    `json:"last_seen_time"`
	AllowedIPs      []string `json:"allowed_ips"`
	Endpoint        string   `json:"endpoint"`
	City            string   `json:"city"`
	CountryCode     string   `json:"country_code"`
	Latitude        float64  `json:"lat"`
	Longitude       float64  `json:"lon"`
	Latency         string   `json:"latency"`
	LatestHandshake int64    `json:"latest_handshake"`
	IsOnline        bool     `json:"is_online"`
}

// ActivityPoint 按小时聚合的流量活动
type ActivityPoint struct {
	Hour  int     `json:"hour"`
	RxSum float64 `json:"rx_sum"`
	TxSum float64 `json:"tx_sum"`
}

// AnalysisReport 分析报告（经典版）
type AnalysisReport struct {
	Peers         []PeerAnalysis  `json:"peers"`
	HourlyProfile []ActivityPoint `json:"hourly_profile"`
}

// AccessLog 客户端访问记录（会话聚合）
type AccessLog struct {
	Timestamp string `json:"timestamp"`
	Endpoint  string `json:"endpoint"`
	RxTotal   int64  `json:"rx_total"`
	TxTotal   int64  `json:"tx_total"`
}

// ================= SSE 结构 =================

// SSEBroker 管理所有 SSE 客户端连接
type SSEBroker struct {
	Clients       map[chan string]bool
	NewClients    chan chan string
	ClosedClients chan chan string
	Message       chan string
	mu            sync.RWMutex
	rateLimit     time.Duration
	lastBroadcast atomic.Value // time.Time
}

// DashboardUpdate SSE 推送的仪表板更新消息
type DashboardUpdate struct {
	Peers     []PeerData `json:"peers"`
	System    SystemInfo `json:"system"`
	Timestamp int64      `json:"timestamp"`
}
