package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RawSnapshot 原始快照数据
type RawSnapshot struct {
	Timestamp time.Time
	Peers     []wgtypes.Peer
}

// ProcessedLog 处理后的日志数据
type ProcessedLog struct {
	Timestamp int64
	PublicKey string
	Endpoint  string
	RxBytes   int64
	TxBytes   int64
	RxRate    float64
	TxRate    float64
	IsOnline  bool
}

// PeerData 客户端详细数据
type PeerData struct {
	PublicKey     string    `json:"public_key"`
	AllowedIPs    []string  `json:"allowed_ips"`
	Endpoint      string    `json:"endpoint"`
	LastHandshake time.Time `json:"last_handshake"`
	ReceiveBytes  int64     `json:"receive_bytes"`
	TransmitBytes int64     `json:"transmit_bytes"`
	Alias         string    `json:"alias"`
	RxRate        float64   `json:"rx_rate"`
	TxRate        float64   `json:"tx_rate"`
	IsOnline      bool      `json:"is_online"`
}

// PeerState 客户端实时状态
type PeerState struct {
	LastRx   int64
	LastTx   int64
	LastSeen time.Time
}

// SystemInfo 系统状态信息
type SystemInfo struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	CPUTemp    float64 `json:"cpu_temp"`
	Uptime     uint64  `json:"uptime"`
	HostName   string  `json:"hostname"`
	OS         string  `json:"os"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Password string `json:"password" binding:"required"`
}

// JwtClaims JWT 载荷
type JwtClaims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

// AddPeerRequest 添加客户端请求
type AddPeerRequest struct {
	ConfigFile string `json:"config_file"` // e.g., "wg0"
	Name       string `json:"name"`        // 备注名
	AllowedIPs string `json:"allowed_ips"` // e.g., "10.0.0.5/32"
}

// PeerAnalysis 客户端分析结果
type PeerAnalysis struct {
	PublicKey    string  `json:"public_key"`
	Alias        string  `json:"alias"`
	TotalRx      int64   `json:"total_rx"`
	TotalTx      int64   `json:"total_tx"`
	Uptime       float64 `json:"uptime_percent"`
	HealthScore  int     `json:"health_score"`
	LastSeenTime int64   `json:"last_seen_time"`
}

// ActivityPoint 活跃度数据点
type ActivityPoint struct {
	Hour  int     `json:"hour"`
	RxSum float64 `json:"rx_sum"`
	TxSum float64 `json:"tx_sum"`
}

// AnalysisReport 分析报告
type AnalysisReport struct {
	Peers         []PeerAnalysis  `json:"peers"`
	HourlyProfile []ActivityPoint `json:"hourly_profile"`
}

// AccessLog 访问日志
type AccessLog struct {
	Timestamp string `json:"timestamp"`
	Endpoint  string `json:"endpoint"`
	RxTotal   int64  `json:"rx_total"`
	TxTotal   int64  `json:"tx_total"`
}

// DashboardUpdate 仪表盘更新数据
type DashboardUpdate struct {
	Peers  []PeerData `json:"peers"`
	System SystemInfo `json:"system"`
}
