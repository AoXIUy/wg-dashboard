package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite" // Pure Go SQLite 驱动，无需 CGO
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ================= 配置区域 =================
var (
	WGInterface string
	ServerPort  string
	DBPath      string
	Retention   int
)

const (
	CollectInterval = 5 * time.Second  // 采集频率
	WriteInterval   = 30 * time.Second // 数据库批量写入频率
	BatchSize       = 100              // 批量写入触发阈值
)

// ================= 数据结构 =================

// RawSnapshot 原始快照（采集层 -> 处理层）
type RawSnapshot struct {
	Timestamp time.Time
	Peers     []wgtypes.Peer
}

// ProcessedLog 处理后的日志（处理层 -> 写入层）
type ProcessedLog struct {
	Timestamp     time.Time
	PublicKey     string
	RxBytes       int64
	TxBytes       int64
	RxRate        float64
	TxRate        float64
	IsOnline      bool
}

// PeerData 前端展示模型
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

// PeerState 内部状态缓存（用于计算速率）
type PeerState struct {
	LastRx        int64
	LastTx        int64
	LastHandshake time.Time
	LastSeen      time.Time
}

// ================= 全局变量 =================
var (
	db *sql.DB
	// 内存缓存：用于 API 快速响应，避免每次查库
	latestPeersCache sync.Map
)

func main() {
	// 1. 参数解析
	flag.StringVar(&WGInterface, "iface", "wg0", "WireGuard 接口名称")
	flag.StringVar(&ServerPort, "port", ":8080", "Web 监听端口")
	flag.StringVar(&DBPath, "db", "./wg_stats.db", "数据库路径")
	flag.IntVar(&Retention, "days", 30, "数据保留天数")
	flag.Parse()

	// 2. 初始化数据库
	initDB()
	defer db.Close()

	// 3. 启动 Pipeline (采集 -> 处理 -> 写入)
	rawChan := make(chan RawSnapshot, 10)
	writeChan := make(chan []ProcessedLog, 5)

	go startCollector(rawChan)
	go startProcessor(rawChan, writeChan)
	go startWriter(writeChan)
	go startCleaner()

	// 4. Web 服务
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, htmlContent)
	})

	api := r.Group("/api")
	{
		api.GET("/peers", getPeers)
		api.GET("/history/:publickey", getPeerHistory)
		api.GET("/stats", getStats)
		api.POST("/alias", setAlias)
		api.GET("/chart/traffic", getTrafficChartData)
	}

	log.Printf("==============================================")
	log.Printf("WireGuard Monitor (Pure Go Optimized)")
	log.Printf("接口: %s | 端口: %s", WGInterface, ServerPort)
	log.Printf("数据库: %s", DBPath)
	log.Printf("==============================================")

	if err := r.Run(ServerPort); err != nil {
		log.Fatal(err)
	}
}

// ================= 数据库层 =================

func initDB() {
	var err error
	db, err = sql.Open("sqlite", DBPath)
	if err != nil {
		log.Fatal("数据库打开失败:", err)
	}

	// 性能调优 (WAL模式大幅提升并发写入性能)
	db.Exec("PRAGMA journal_mode = WAL;")
	db.Exec("PRAGMA synchronous = NORMAL;")
	db.Exec("PRAGMA temp_store = MEMORY;")

	schema := `
	CREATE TABLE IF NOT EXISTS traffic_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		peer_public_key TEXT NOT NULL,
		rx_bytes INTEGER NOT NULL,
		tx_bytes INTEGER NOT NULL,
		rx_rate REAL DEFAULT 0,
		tx_rate REAL DEFAULT 0,
		is_online BOOLEAN DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_peer_time ON traffic_history(peer_public_key, timestamp);
	CREATE INDEX IF NOT EXISTS idx_time ON traffic_history(timestamp);

	CREATE TABLE IF NOT EXISTS peer_aliases (
		public_key TEXT PRIMARY KEY,
		alias TEXT NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		log.Fatal("建表失败:", err)
	}
}

// ================= 核心 Pipeline =================

// 1. 采集器 (Collector)
func startCollector(out chan<- RawSnapshot) {
	var client *wgctrl.Client
	var err error

	reconnect := func() {
		if client != nil { client.Close() }
		client, err = wgctrl.New()
		if err != nil {
			log.Printf("WireGuard 连接失败: %v", err)
		}
	}

	reconnect()
	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()

	for range ticker.C {
		if client == nil {
			reconnect()
			if client == nil { continue }
		}

		device, err := client.Device(WGInterface)
		if err != nil {
			log.Printf("获取设备信息失败 (尝试重连): %v", err)
			reconnect()
			continue
		}

		// 非阻塞发送
		select {
		case out <- RawSnapshot{Timestamp: time.Now(), Peers: device.Peers}:
		default:
			// log.Println("警告: 处理通道已满，跳过本次采集")
		}
	}
}

// 2. 处理器 (Processor)
func startProcessor(in <-chan RawSnapshot, out chan<- []ProcessedLog) {
	stateMap := make(map[string]*PeerState)
	var buffer []ProcessedLog
	flushTicker := time.NewTicker(WriteInterval)

	flush := func() {
		if len(buffer) > 0 {
			batch := make([]ProcessedLog, len(buffer))
			copy(batch, buffer)
			select {
			case out <- batch:
			default:
			}
			buffer = buffer[:0]
		}
	}

	for {
		select {
		case snap := <-in:
			for _, p := range snap.Peers {
				pk := p.PublicKey.String()
				
				state, exists := stateMap[pk]
				if !exists {
					state = &PeerState{LastRx: p.ReceiveBytes, LastTx: p.TransmitBytes, LastSeen: snap.Timestamp}
					stateMap[pk] = state
				}

				// 计算速率 (KB/s)
				timeDiff := snap.Timestamp.Sub(state.LastSeen).Seconds()
				var rxRate, txRate float64
				if timeDiff > 0 {
					if p.ReceiveBytes >= state.LastRx {
						rxRate = float64(p.ReceiveBytes - state.LastRx) / timeDiff / 1024
					}
					if p.TransmitBytes >= state.LastTx {
						txRate = float64(p.TransmitBytes - state.LastTx) / timeDiff / 1024
					}
				}

				// 在线状态判定：只要 3 分钟内有握手即视为在线 (标准 WireGuard 逻辑)
				isOnline := !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < 3*time.Minute

				state.LastRx = p.ReceiveBytes
				state.LastTx = p.TransmitBytes
				state.LastHandshake = p.LastHandshakeTime
				state.LastSeen = snap.Timestamp

				logEntry := ProcessedLog{
					Timestamp: snap.Timestamp,
					PublicKey: pk,
					RxBytes:   p.ReceiveBytes,
					TxBytes:   p.TransmitBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					IsOnline:  isOnline,
				}

				buffer = append(buffer, logEntry)
				latestPeersCache.Store(pk, logEntry)
			}

			if len(buffer) >= BatchSize {
				flush()
			}

		case <-flushTicker.C:
			flush()
		}
	}
}

// 3. 写入器 (Writer)
func startWriter(in <-chan []ProcessedLog) {
	for batch := range in {
		if len(batch) == 0 { continue }

		tx, err := db.Begin()
		if err != nil { continue }

		stmt, err := tx.Prepare(`
			INSERT INTO traffic_history (timestamp, peer_public_key, rx_bytes, tx_bytes, rx_rate, tx_rate, is_online)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			tx.Rollback()
			continue
		}

		for _, logEntry := range batch {
			stmt.Exec(
				logEntry.Timestamp, logEntry.PublicKey,
				logEntry.RxBytes, logEntry.TxBytes,
				logEntry.RxRate, logEntry.TxRate, logEntry.IsOnline,
			)
		}
		stmt.Close()
		tx.Commit()
	}
}

// 4. 清理器 (Cleaner)
func startCleaner() {
	if Retention <= 0 { return }
	for {
		time.Sleep(24 * time.Hour)
		log.Println("执行历史数据清理...")
		db.Exec(`DELETE FROM traffic_history WHERE timestamp < datetime('now', '-' || ? || ' days')`, Retention)
	}
}

// ================= API Handlers =================

func getPeers(c *gin.Context) {
	client, _ := wgctrl.New()
	defer client.Close()
	
	device, err := client.Device(WGInterface)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	aliasMap := make(map[string]string)
	rows, _ := db.Query("SELECT public_key, alias FROM peer_aliases")
	if rows != nil {
		for rows.Next() {
			var pk, a string
			rows.Scan(&pk, &a)
			aliasMap[pk] = a
		}
		rows.Close()
	}

	var peers []PeerData
	for _, p := range device.Peers {
		pk := p.PublicKey.String()
		
		var ips []string
		for _, ip := range p.AllowedIPs {
			ips = append(ips, ip.String())
		}
		
		ep := "未连接"
		if p.Endpoint != nil {
			ep = p.Endpoint.String()
		}

		var rxRate, txRate float64
		var isOnline bool
		
		if val, ok := latestPeersCache.Load(pk); ok {
			logEntry := val.(ProcessedLog)
			rxRate = logEntry.RxRate
			txRate = logEntry.TxRate
			isOnline = logEntry.IsOnline
		} else {
			// 如果缓存没有，用握手时间兜底判断
			isOnline = !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < 3*time.Minute
		}

		peers = append(peers, PeerData{
			PublicKey:     pk,
			AllowedIPs:    ips,
			Endpoint:      ep,
			LastHandshake: p.LastHandshakeTime,
			ReceiveBytes:  p.ReceiveBytes,
			TransmitBytes: p.TransmitBytes,
			Alias:         aliasMap[pk],
			RxRate:        rxRate,
			TxRate:        txRate,
			IsOnline:      isOnline,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		// 在线优先，然后按别名/IP排序
		if peers[i].IsOnline != peers[j].IsOnline {
			return peers[i].IsOnline
		}
		return peers[i].AllowedIPs[0] < peers[j].AllowedIPs[0]
	})

	c.JSON(200, gin.H{
		"interface": device.Name,
		"port":      device.ListenPort,
		"peers":     peers,
	})
}

func getPeerHistory(c *gin.Context) {
	pk := c.Param("publickey")
	period := c.DefaultQuery("period", "24h")

	var hours int
	switch period {
	case "7d": hours = 24 * 7
	case "30d": hours = 24 * 30
	default: hours = 24
	}

	groupBy := "strftime('%Y-%m-%d %H:%M', timestamp)"
	if hours > 24 {
		groupBy = "strftime('%Y-%m-%d %H', timestamp)"
	}

	query := fmt.Sprintf(`
		SELECT 
			%s as time_bucket,
			AVG(rx_rate), AVG(tx_rate),
			MAX(rx_bytes) - MIN(rx_bytes), MAX(tx_bytes) - MIN(tx_bytes)
		FROM traffic_history
		WHERE peer_public_key = ? AND timestamp > datetime('now', '-%d hours')
		GROUP BY time_bucket
		ORDER BY time_bucket ASC
	`, groupBy, hours)

	rows, err := db.Query(query, pk)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var labels []string
	var rxData, txData []float64
	var rxVol, txVol []int64

	for rows.Next() {
		var t string
		var rx, tx float64
		var rVol, tVol sql.NullInt64 
		
		if err := rows.Scan(&t, &rx, &tx, &rVol, &tVol); err == nil {
			if len(t) > 11 {
				labels = append(labels, t[11:])
			} else {
				labels = append(labels, t)
			}
			rxData = append(rxData, rx)
			txData = append(txData, tx)
			rxVol = append(rxVol, rVol.Int64)
			txVol = append(txVol, tVol.Int64)
		}
	}

	c.JSON(200, gin.H{
		"labels": labels,
		"rates":  gin.H{"rx": rxData, "tx": txData},
		"volume": gin.H{"rx": rxVol, "tx": txVol},
	})
}

func getTrafficChartData(c *gin.Context) {
	query := `
		SELECT 
			strftime('%Y-%m-%d %H:%M', timestamp) as tb,
			SUM(rx_rate), SUM(tx_rate)
		FROM traffic_history
		WHERE timestamp > datetime('now', '-24 hours')
		GROUP BY tb
		ORDER BY tb
	`

	rows, err := db.Query(query)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var labels []string
	var rx, tx []float64

	for rows.Next() {
		var t string
		var r, x float64
		if err := rows.Scan(&t, &r, &x); err == nil {
			if len(t) > 11 {
				labels = append(labels, t[11:])
			} else {
				labels = append(labels, t)
			}
			rx = append(rx, r)
			tx = append(tx, x)
		}
	}

	c.JSON(200, gin.H{"labels": labels, "rx": rx, "tx": tx})
}

func getStats(c *gin.Context) {
	topQuery := `
		SELECT 
			t.peer_public_key,
			COALESCE(a.alias, '') as alias,
			MAX(t.rx_bytes) as total_rx,
			MAX(t.tx_bytes) as total_tx
		FROM traffic_history t
		LEFT JOIN peer_aliases a ON t.peer_public_key = a.public_key
		WHERE t.timestamp > datetime('now', '-24 hours')
		GROUP BY t.peer_public_key
		ORDER BY total_rx DESC
		LIMIT 5
	`
	rows, _ := db.Query(topQuery)
	var topPeers []gin.H
	if rows != nil {
		for rows.Next() {
			var pk, alias string
			var rx, tx int64
			rows.Scan(&pk, &alias, &rx, &tx)
			topPeers = append(topPeers, gin.H{"public_key": pk, "alias": alias, "total_rx": rx, "total_tx": tx})
		}
		rows.Close()
	}
	c.JSON(200, gin.H{"top_peers": topPeers})
}

func setAlias(c *gin.Context) {
	var req struct { PublicKey string `json:"public_key"`; Alias string `json:"alias"` }
	if err := c.BindJSON(&req); err != nil { return }
	db.Exec(`INSERT INTO peer_aliases (public_key, alias) VALUES (?, ?) 
		ON CONFLICT(public_key) DO UPDATE SET alias = excluded.alias`, req.PublicKey, req.Alias)
	c.JSON(200, gin.H{"status": "ok"})
}

// ================= 前端代码 (优化版) =================
const htmlContent = `
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireGuard Monitor</title>
    <script src="https://cdn.staticfile.org/vue/3.3.4/vue.global.prod.min.js"></script>
    <script src="https://cdn.staticfile.org/axios/1.6.0/axios.min.js"></script>
    <script src="https://cdn.staticfile.org/Chart.js/4.4.0/chart.umd.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        [v-cloak] { display: none; }
        .fade-enter-active, .fade-leave-active { transition: opacity 0.3s; }
        .fade-enter-from, .fade-leave-to { opacity: 0; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen text-slate-800 font-sans">
    <div id="app" v-cloak class="max-w-7xl mx-auto p-4 lg:p-6 space-y-6">
        
        <div class="flex flex-col md:flex-row justify-between items-center bg-white p-4 rounded-xl shadow-sm border border-slate-200">
            <div class="flex items-center gap-3">
                <div class="bg-blue-600 p-2 rounded-lg text-white">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                </div>
                <div>
                    <h1 class="font-bold text-lg">WireGuard Monitor</h1>
                    <div class="flex items-center gap-2 text-xs text-slate-500">
                        <span v-if="loading" class="text-blue-600 animate-pulse">● 更新中...</span>
                        <span v-else>● {{ meta.interface }}:{{ meta.port }}</span>
                    </div>
                </div>
            </div>
            <div class="flex bg-slate-100 p-1 rounded-lg mt-4 md:mt-0">
                <button @click="view='list'" :class="view==='list'?'bg-white text-blue-600 shadow-sm':'text-slate-500 hover:text-slate-700'" class="px-6 py-2 rounded-md text-sm font-medium transition-all">列表监控</button>
                <button @click="view='stats'" :class="view==='stats'?'bg-white text-blue-600 shadow-sm':'text-slate-500 hover:text-slate-700'" class="px-6 py-2 rounded-md text-sm font-medium transition-all">流量分析</button>
            </div>
        </div>

        <div v-if="view === 'list'" class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-white p-5 rounded-xl shadow-sm border border-slate-200">
                    <div class="text-xs text-slate-400 font-bold uppercase">在线设备</div>
                    <div class="text-2xl font-bold text-slate-700 mt-1">{{ onlineCount }} <span class="text-sm text-slate-300 font-normal">/ {{ peers.length }}</span></div>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-slate-200">
                    <div class="text-xs text-slate-400 font-bold uppercase">实时总下载</div>
                    <div class="text-2xl font-bold text-blue-600 mt-1">{{ fmtRate(totalRxRate) }}</div>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-slate-200">
                    <div class="text-xs text-slate-400 font-bold uppercase">实时总上传</div>
                    <div class="text-2xl font-bold text-purple-600 mt-1">{{ fmtRate(totalTxRate) }}</div>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-slate-200">
                    <div class="text-xs text-slate-400 font-bold uppercase">状态</div>
                    <div class="text-sm font-medium text-emerald-600 mt-2 flex items-center gap-2">
                        <span class="relative flex h-3 w-3"><span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span><span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span></span>
                        运行正常
                    </div>
                </div>
            </div>

            <div class="lg:col-span-3 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm whitespace-nowrap">
                        <thead class="bg-slate-50 text-slate-500 font-semibold border-b border-slate-200">
                            <tr>
                                <th class="p-4">客户端 / 别名</th>
                                <th class="p-4">在线状态</th>
                                <th class="p-4">实时速率 (Rx / Tx)</th>
                                <th class="p-4">累计流量 (In / Out)</th>
                                <th class="p-4 text-right">操作</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100">
                            <tr v-for="p in peers" :key="p.public_key" :class="p.is_online ? 'bg-blue-50/30' : 'hover:bg-slate-50'" class="transition-colors">
                                <td class="p-4">
                                    <div class="flex flex-col">
                                        <div class="flex items-center gap-2">
                                            <span v-if="editing!==p.public_key" @click="editAlias(p)" class="font-bold text-slate-700 cursor-pointer border-b border-dashed border-transparent hover:border-blue-400">{{ p.alias || '无别名' }}</span>
                                            <input v-else v-model="tempAlias" @blur="saveAlias(p.public_key)" @keyup.enter="saveAlias(p.public_key)" class="border-b-2 border-blue-500 bg-transparent outline-none font-bold text-slate-700 w-32" autofocus placeholder="输入别名...">
                                        </div>
                                        <span class="text-xs text-slate-400 font-mono mt-1">{{ p.allowed_ips[0] }}</span>
                                    </div>
                                </td>
                                <td class="p-4">
                                    <div class="flex items-center gap-2">
                                        <span class="w-2.5 h-2.5 rounded-full" :class="p.is_online ? 'bg-emerald-500 shadow-sm shadow-emerald-200' : 'bg-slate-300'"></span>
                                        <div class="flex flex-col">
                                            <span :class="p.is_online ? 'text-emerald-700 font-medium' : 'text-slate-400'">{{ p.is_online ? '在线' : '离线' }}</span>
                                            <span class="text-[10px] text-slate-400">{{ timeAgo(p.last_handshake) }}</span>
                                        </div>
                                    </div>
                                </td>
                                <td class="p-4 font-mono text-xs">
                                    <div class="text-blue-600 mb-1">↓ {{ fmtRate(p.rx_rate) }}</div>
                                    <div class="text-purple-600">↑ {{ fmtRate(p.tx_rate) }}</div>
                                </td>
                                <td class="p-4 text-xs text-slate-600">
                                    <div>In: {{ fmtBytes(p.receive_bytes) }}</div>
                                    <div>Out: {{ fmtBytes(p.transmit_bytes) }}</div>
                                </td>
                                <td class="p-4 text-right">
                                    <button @click="openDetail(p)" class="text-xs bg-white border border-slate-200 hover:text-blue-600 text-slate-600 px-3 py-1.5 rounded-lg transition-all shadow-sm">
                                        历史详情
                                    </button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div v-if="view === 'stats'" class="space-y-6">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                 <div class="flex justify-between items-center mb-6">
                    <h3 class="font-bold text-slate-800">全网流量趋势 (24小时)</h3>
                    <button @click="fetchMainStats" class="text-xs text-blue-600 hover:underline">刷新</button>
                 </div>
                 <div class="h-80 relative w-full"><canvas id="mainChart"></canvas></div>
            </div>
        </div>

        <Transition name="fade">
            <div v-if="modalPeer" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50" @click.self="modalPeer=null">
                <div class="bg-white rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto p-6 shadow-2xl">
                    <div class="flex justify-between items-start mb-6 border-b pb-4">
                        <div>
                            <h2 class="text-xl font-bold">{{ modalPeer.alias || '节点详情' }}</h2>
                            <p class="text-xs text-slate-500 font-mono mt-1">{{ modalPeer.public_key }}</p>
                        </div>
                        <div class="flex items-center gap-3">
                            <select v-model="historyPeriod" @change="fetchHistory(modalPeer.public_key)" class="bg-slate-50 border rounded-lg px-3 py-1.5 text-sm">
                                <option value="24h">24 小时</option>
                                <option value="7d">7 天</option>
                                <option value="30d">30 天</option>
                            </select>
                            <button @click="modalPeer=null" class="text-slate-400 hover:text-slate-700 font-bold text-xl">&times;</button>
                        </div>
                    </div>
                    <div class="relative h-72 bg-slate-50 rounded-xl p-4 mb-6 border">
                        <canvas id="detailChart"></canvas>
                        <div v-if="chartLoading" class="absolute inset-0 flex items-center justify-center bg-white/50"><div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div></div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-blue-50 p-4 rounded-xl text-center"><div class="text-xs text-blue-500 font-bold uppercase">区间总下载</div><div class="font-bold text-xl text-blue-700">{{ fmtBytes(historyStats.totalRx) }}</div></div>
                        <div class="bg-purple-50 p-4 rounded-xl text-center"><div class="text-xs text-purple-500 font-bold uppercase">区间总上传</div><div class="font-bold text-xl text-purple-700">{{ fmtBytes(historyStats.totalTx) }}</div></div>
                    </div>
                </div>
            </div>
        </Transition>
    </div>

    <script>
        const { createApp, ref, onMounted, onUnmounted, computed, watch } = Vue;
        createApp({
            setup() {
                const peers = ref([]);
                const meta = ref({interface: '...', port: '...'});
                const view = ref('list');
                const editing = ref(null);
                const tempAlias = ref('');
                const loading = ref(false);
                const modalPeer = ref(null);
                const historyPeriod = ref('24h');
                const historyStats = ref({totalRx: 0, totalTx: 0});
                const chartLoading = ref(false);
                
                let chartInst = null, mainChartInst = null, pollTimer = null;

                const fmtBytes = (b) => {
                    if (b===0) return '0 B';
                    const k=1024, sizes=['B','KB','MB','GB','TB'];
                    const i=Math.floor(Math.log(b)/Math.log(k));
                    return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+sizes[i];
                };
                const fmtRate = (kb) => fmtBytes(kb*1024) + '/s';
                
                const timeAgo = (t) => {
                    if (!t || t.startsWith('0001')) return '从未连接';
                    const diff = (new Date() - new Date(t))/1000;
                    if (diff < 60) return '刚刚';
                    if (diff < 3600) return Math.floor(diff/60)+' 分钟前';
                    if (diff < 86400) return Math.floor(diff/3600)+' 小时前';
                    return Math.floor(diff/86400)+' 天前';
                };

                const totalRxRate = computed(() => peers.value.reduce((a,b)=>a+(b.rx_rate||0),0));
                const totalTxRate = computed(() => peers.value.reduce((a,b)=>a+(b.tx_rate||0),0));
                const onlineCount = computed(() => peers.value.filter(p=>p.is_online).length);

                const fetchPeers = async () => {
                    loading.value = true;
                    try {
                        const res = await axios.get('/api/peers');
                        peers.value = res.data.peers || [];
                        meta.value = {interface: res.data.interface, port: res.data.port};
                    } catch(e){} finally { loading.value = false; }
                };

                const saveAlias = async (pk) => {
                    if(!pk) return;
                    await axios.post('/api/alias', {public_key: pk, alias: tempAlias.value});
                    editing.value=null; fetchPeers();
                };

                const openDetail = (p) => { modalPeer.value = p; fetchHistory(p.public_key); };

                const fetchHistory = async (pk) => {
                    chartLoading.value = true;
                    try {
                        const res = await axios.get('/api/history/'+pk+'?period='+historyPeriod.value);
                        const data = res.data;
                        historyStats.value.totalRx = (data.volume?.rx||[]).reduce((a,b)=>a+b,0);
                        historyStats.value.totalTx = (data.volume?.tx||[]).reduce((a,b)=>a+b,0);
                        renderChart('detailChart', data.labels, data.rates.rx, data.rates.tx, true);
                    } finally { chartLoading.value = false; }
                };

                const fetchMainStats = async () => {
                    const res = await axios.get('/api/chart/traffic');
                    renderChart('mainChart', res.data.labels, res.data.rx, res.data.tx, false);
                };

                const renderChart = (id, labels, rx, tx, fill) => {
                    const ctx = document.getElementById(id);
                    if (!ctx) return;
                    let inst = id==='detailChart'?chartInst:mainChartInst;
                    if (inst) inst.destroy();
                    
                    const cfg = {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [
                                { label: '下载 (KB/s)', data: rx, borderColor: '#2563eb', tension: 0.3, fill: fill, backgroundColor: '#2563eb10', pointRadius: 0, pointHitRadius: 10 },
                                { label: '上传 (KB/s)', data: tx, borderColor: '#9333ea', tension: 0.3, fill: fill, backgroundColor: '#9333ea10', pointRadius: 0, pointHitRadius: 10 }
                            ]
                        },
                        options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false }, scales: { y: { beginAtZero: true } } }
                    };
                    
                    if(id==='detailChart') chartInst = new Chart(ctx, cfg);
                    else mainChartInst = new Chart(ctx, cfg);
                };

                const handleVisibility = () => {
                    document.hidden ? clearInterval(pollTimer) : (fetchPeers(), pollTimer = setInterval(fetchPeers, 3000));
                };

                watch(view, (v) => { if(v==='stats') setTimeout(fetchMainStats, 100); });

                onMounted(() => {
                    fetchPeers();
                    pollTimer = setInterval(fetchPeers, 3000);
                    document.addEventListener('visibilitychange', handleVisibility);
                });
                onUnmounted(() => {
                    clearInterval(pollTimer);
                    document.removeEventListener('visibilitychange', handleVisibility);
                });

                return {
                    peers, meta, view, editing, tempAlias, loading, modalPeer, historyPeriod, historyStats, chartLoading,
                    totalRxRate, totalTxRate, onlineCount,
                    fmtBytes, fmtRate, timeAgo, saveAlias: saveAlias, openDetail, fetchHistory, fetchMainStats,
                    editAlias: (p) => { editing.value = p.public_key; tempAlias.value = p.alias||''; }
                };
            }
        }).mount('#app');
    </script>
</body>
</html>
`