package config

import (
	"regexp"
	"time"
)

// ================= 常量定义 =================
const (
	CollectInterval     = 2 * time.Second
	WriteInterval       = 6 * time.Second
	BatchSize           = 200 // Updated from 10 to 200 during optimization
	MaxAliasLength      = 100
	MaxPublicKeyLength  = 200
	OnlineThreshold     = 3 * time.Minute
	DBMaxOpenConns      = 25
	DBMaxIdleConns      = 5
	DBConnMaxLifetime   = 5 * time.Minute
	CacheTTL            = 10 * time.Minute
	ShutdownTimeout     = 30 * time.Second
	BitsPerByte         = 8.0
	MegabitsPerSecond   = 1000000.0
	TokenExpireDuration = 24 * time.Hour
)

// ================= 全局配置变量 =================
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

var (
	PublicKeyRegex = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)
