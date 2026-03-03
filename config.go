package main

import (
	"database/sql"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
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
	RedisAddr     string
	Retention     int
	AdminPassword string
	JWTSecret     string
	GeoCityPath   string
	GeoASNPath    string
)

// ================= 全局变量 =================
var (
	db             *sql.DB
	rdb            *redis.Client
	configMu       sync.Mutex
	publicKeyRegex = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	logger         *log.Logger
	ipProvider     ipapi.Provider
	sseBroker      *SSEBroker
	redisEnabled   bool
	aliasCache     *AliasCache
	trafficBuffer  *TrafficBuffer
	latencyCache   *LatencyCache
	metrics        *Metrics
	analysisEngine *AnalysisEngine
)
