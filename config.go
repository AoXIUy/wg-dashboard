package main

import (
	"database/sql"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"wg-dashboard/pkg/ipapi"
)

// ================= 常量定义 =================
const (
	CollectInterval     = 2 * time.Second
	WriteInterval       = 6 * time.Second
	BatchSize           = 100
	MaxAliasLength      = 100
	MaxPublicKeyLength  = 200
	OnlineThreshold     = 3 * time.Minute
	DBMaxOpenConns      = 50
	DBMaxIdleConns      = 10
	DBConnMaxLifetime   = 10 * time.Minute
	DBConnMaxIdleTime   = 5 * time.Minute
	CacheTTL            = 5 * time.Minute
	ShutdownTimeout     = 30 * time.Second
	BitsPerByte         = 8.0
	MegabitsPerSecond   = 1000000.0
	TokenExpireDuration = 24 * time.Hour
	SSEBroadcastLimit   = 100 * time.Millisecond
	MaxRetries          = 3
	BufferMaxSize       = 1000
)

// ================= 命令行配置变量 =================
var (
	WGInterface   string
	ServerPort    string
	MySQLDSN      string
	Retention     int
	AdminPassword string
	JWTSecret     string
	GeoCityPath   string
	GeoASNPath    string
	IsMockMode    bool
	WGConfigDir   string
)

// ================= 全局变量 =================
var (
	db             *sql.DB
	configMu       sync.Mutex
	publicKeyRegex = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	logger         = log.New(os.Stdout, "[WG-Monitor] ", log.LstdFlags|log.Lshortfile)
	ipProvider     ipapi.Provider
	sseBroker      *SSEBroker
	aliasCache     *AliasCache
	trafficBuffer  *TrafficBuffer
	latencyCache   *LatencyCache
	metrics        *Metrics
	analysisEngine *AnalysisEngine
	wgExecutor     WireGuardExecutor

	// 性能优化：缓存最近一次采集周期处理后的 PeerData，供 broadcastUpdate 和 startPinger 复用，
	// 避免各自重复查询内核
	cachedPeers   []PeerData
	cachedPeersMu sync.RWMutex
)
