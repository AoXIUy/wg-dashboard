package main

import (
	"database/sql"
	"log"
	"regexp"
	"sync"
	"time"

	"wg-dashboard/pkg/ipapi"
)

// ================= 常量定义 =================
const (
	CollectInterval     = 5 * time.Second  // RK3399 优化：从 2s 提升到 5s，减少 60% 写入
	WriteInterval       = 30 * time.Second // RK3399 优化：从 6s 提升到 30s，合并更多写入减少 fsync
	BatchSize           = 100
	MaxAliasLength      = 100
	MaxPublicKeyLength  = 200
	OnlineThreshold     = 3 * time.Minute
	CacheTTL            = 5 * time.Minute
	ShutdownTimeout     = 30 * time.Second
	BitsPerByte         = 8.0
	MegabitsPerSecond   = 1000000.0
	TokenExpireDuration = 24 * time.Hour
	SSEBroadcastLimit   = 100 * time.Millisecond
	MaxRetries          = 3
	BufferMaxSize       = 500 // RK3399 优化：从 1000 降到 500，配合更长的写入间隔
)

// ================= 命令行配置变量 =================
var (
	WGInterface   string
	ServerPort    string
	DBPath        string // SQLite 数据库路径（替代 MySQLDSN）
	Retention     int
	AdminPassword string
	JWTSecret     string
	GeoCityPath   string
	GeoASNPath    string
)

// ================= 全局变量 =================
var (
	db             *sql.DB
	configMu       sync.Mutex
	publicKeyRegex = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	logger         *log.Logger
	ipProvider     ipapi.Provider
	sseBroker      *SSEBroker
	aliasCache     *AliasCache
	trafficBuffer  *TrafficBuffer
	latencyCache   *LatencyCache
	metrics        *Metrics
	analysisEngine *AnalysisEngine

	// 性能优化：缓存最近一次采集周期处理后的 PeerData，供 broadcastUpdate 和 startPinger 复用，
	// 避免各自重复创建 wgctrl.Client 并再次向内核发起查询
	cachedPeers   []PeerData
	cachedPeersMu sync.RWMutex
)
