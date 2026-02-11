package service

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/oschwald/geoip2-golang"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"wg-dashboard/pkg/config"
	"wg-dashboard/pkg/db"
	"wg-dashboard/pkg/models"
)

var (
	TrafficQueue     chan models.ProcessedLog
	sharedWGClient   *wgctrl.Client
	sharedWGClientMu sync.Mutex
	sseBroker        *SSEBroker
	geoCity          *geoip2.Reader
	geoASN           *geoip2.Reader
)

// SSEBroker 结构
type SSEBroker struct {
	Clients       map[chan string]bool
	NewClients    chan chan string
	ClosedClients chan chan string
	Message       chan string
	mu            sync.RWMutex
}

// InitService 初始化服务
func InitService() {
	TrafficQueue = make(chan models.ProcessedLog, 2000)
	sseBroker = &SSEBroker{
		Clients:       make(map[chan string]bool),
		NewClients:    make(chan chan string),
		ClosedClients: make(chan chan string),
		Message:       make(chan string),
	}
	go startSSEBroker()
}

// GetSharedWGClient 获取共享的 WireGuard Client
func GetSharedWGClient() (*wgctrl.Client, error) {
	sharedWGClientMu.Lock()
	defer sharedWGClientMu.Unlock()

	if sharedWGClient != nil {
		return sharedWGClient, nil
	}

	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	sharedWGClient = c
	return sharedWGClient, nil
}

// CloseSharedWGClient 在程序退出时清理
func CloseSharedWGClient() {
	sharedWGClientMu.Lock()
	defer sharedWGClientMu.Unlock()
	if sharedWGClient != nil {
		sharedWGClient.Close()
		sharedWGClient = nil
	}
}

// CollectSystemInfo 收集系统信息
func CollectSystemInfo() models.SystemInfo {
	var sys models.SystemInfo
	if percent, err := cpu.Percent(0, false); err == nil && len(percent) > 0 {
		sys.CPUPercent = percent[0]
	}
	if v, err := mem.VirtualMemory(); err == nil {
		sys.MemPercent = v.UsedPercent
	}
	if h, err := host.Info(); err == nil {
		sys.Uptime = h.Uptime
		sys.HostName = h.Hostname
		sys.OS = h.Platform + " " + h.PlatformVersion
	}
	if temps, err := host.SensorsTemperatures(); err == nil {
		for _, t := range temps {
			if t.Temperature > sys.CPUTemp {
				sys.CPUTemp = t.Temperature
			}
		}
	}
	return sys
}

// CollectPeersData 收集 Peer 数据
func CollectPeersData() ([]models.PeerData, string, int, error) {
	client, err := GetSharedWGClient()
	if err != nil {
		return nil, "", 0, err
	}

	device, err := client.Device(config.WGInterface)
	if err != nil {
		CloseSharedWGClient()
		return nil, "", 0, err
	}

	aliasMap, _ := db.GetAliases()

	var peers []models.PeerData
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

		// 从 Redis 获取实时状态
		if db.RedisEnabled {
			val, err := db.GetRedisPeerState(context.Background(), pk)
			if err == nil && len(val) > 0 {
				rxRate, _ = strconv.ParseFloat(val["rx_rate"], 64)
				txRate, _ = strconv.ParseFloat(val["tx_rate"], 64)
				onlineInt, _ := strconv.Atoi(val["is_online"])
				isOnline = onlineInt == 1
			}
		}

		// 如果 Redis 没有数据，回退到基于握手时间的判断
		if !isOnline && !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < config.OnlineThreshold {
			isOnline = true
		}

		peers = append(peers, models.PeerData{
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
		if peers[i].IsOnline != peers[j].IsOnline {
			return peers[i].IsOnline
		}
		if len(peers[i].AllowedIPs) > 0 && len(peers[j].AllowedIPs) > 0 {
			return peers[i].AllowedIPs[0] < peers[j].AllowedIPs[0]
		}
		return false
	})

	return peers, device.Name, device.ListenPort, nil
}

// StartCollector 启动数据采集器
func StartCollector(ctx context.Context, out chan<- models.RawSnapshot) {
	log.Println("采集器已启动")
	defer log.Println("采集器已停止")

	var client *wgctrl.Client
	var err error

	reconnect := func() error {
		if client != nil {
			client.Close()
		}
		client, err = wgctrl.New()
		if err != nil {
			log.Printf("WireGuard 连接失败: %v", err)
			return err
		}
		return nil
	}

	if err := reconnect(); err != nil {
		log.Printf("初始连接失败，将在后续重试")
	}

	ticker := time.NewTicker(config.CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if client != nil {
				client.Close()
			}
			close(out)
			return
		case <-ticker.C:
			if client == nil {
				if err := reconnect(); err != nil {
					continue
				}
			}

			device, err := client.Device(config.WGInterface)
			if err != nil {
				reconnect()
				continue
			}

			select {
			case out <- models.RawSnapshot{Timestamp: time.Now(), Peers: device.Peers}:
			case <-ctx.Done():
				return
			default:
			}
		}
	}
}

// StartProcessor 启动数据处理器
func StartProcessor(ctx context.Context, in <-chan models.RawSnapshot) {
	log.Println("处理器已启动")
	stateMap := make(map[string]*models.PeerState)

	for {
		select {
		case <-ctx.Done():
			return
		case snap, ok := <-in:
			if !ok {
				return
			}

			for _, p := range snap.Peers {
				pk := p.PublicKey.String()
				state, exists := stateMap[pk]

				if !exists {
					state = &models.PeerState{
						LastRx:   p.ReceiveBytes,
						LastTx:   p.TransmitBytes,
						LastSeen: snap.Timestamp,
					}
					stateMap[pk] = state
				}

				timeDiff := snap.Timestamp.Sub(state.LastSeen).Seconds()
				var rxRate, txRate float64

				if timeDiff > 0 {
					if p.ReceiveBytes >= state.LastRx {
						rxRate = float64(p.ReceiveBytes-state.LastRx) * config.BitsPerByte / timeDiff / config.MegabitsPerSecond
					}
					if p.TransmitBytes >= state.LastTx {
						txRate = float64(p.TransmitBytes-state.LastTx) * config.BitsPerByte / timeDiff / config.MegabitsPerSecond
					}
				}

				isOnline := !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < config.OnlineThreshold
				state.LastRx = p.ReceiveBytes
				state.LastTx = p.TransmitBytes
				state.LastSeen = snap.Timestamp

				epStr := ""
				if p.Endpoint != nil {
					epStr = p.Endpoint.IP.String()
				}

				logEntry := models.ProcessedLog{
					Timestamp: snap.Timestamp.Unix(),
					PublicKey: pk,
					Endpoint:  epStr,
					RxBytes:   p.ReceiveBytes,
					TxBytes:   p.TransmitBytes,
					RxRate:    rxRate,
					TxRate:    txRate,
					IsOnline:  isOnline,
				}

				// 1. 写入内存队列 (用于持久化)
				select {
				case TrafficQueue <- logEntry:
				default:
					log.Println("警告: 内存队列已满，丢弃日志")
				}

				// 2. 更新 Redis 实时状态 (仅用于前端展示)
				if db.RedisEnabled {
					onlineVal := 0
					if isOnline {
						onlineVal = 1
					}
					db.UpdateRedisPeerState(ctx, pk, map[string]interface{}{
						"rx_rate":   rxRate,
						"tx_rate":   txRate,
						"is_online": onlineVal,
						"endpoint":  epStr,
						"last_seen": snap.Timestamp.Unix(),
					})
				}
			}

			if db.RedisEnabled {
				// 3. 触发 SSE 广播 (通过 Redis Pub/Sub)
				peers, _, _, _ := CollectPeersData()
				update := models.DashboardUpdate{
					Peers:  peers,
					System: CollectSystemInfo(),
				}
				db.PublishBroadcast(ctx, update)
			}
		}
	}
}

// StartAsyncWriter 启动异步写入器
func StartAsyncWriter(ctx context.Context) {
	log.Println("异步写入器已启动 (Memory -> MySQL)")
	// Check config and fix if necessary (BatchSize is defined in config now)
	const FlushInterval = 5 * time.Second

	var batch []models.ProcessedLog
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			db.BulkInsertTrafficHistory(batch)
			return
		case <-ticker.C:
			if len(batch) > 0 {
				if err := db.BulkInsertTrafficHistory(batch); err != nil {
					log.Printf("MySQL 批量写入失败: %v", err)
				} else {
					batch = batch[:0]
				}
			}
		case logEntry := <-TrafficQueue:
			batch = append(batch, logEntry)
			if len(batch) >= config.BatchSize {
				if err := db.BulkInsertTrafficHistory(batch); err != nil {
					log.Printf("MySQL 批量写入失败: %v", err)
				} else {
					batch = batch[:0]
				}
			}
		}
	}
}

// StartCleaner 启动清理器
func StartCleaner(ctx context.Context) {
	if config.Retention <= 0 {
		return
	}
	log.Printf("数据清理器已启动 (保留 %d 天)", config.Retention)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	
	clean := func() {
		if rows, err := db.CleanOldData(config.Retention); err == nil && rows > 0 {
			log.Printf("已清理 %d 条旧数据记录", rows)
		} else if err != nil {
			log.Printf("清理旧数据失败: %v", err)
		}
	}

	clean()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			clean()
		}
	}
}

// StartRedisBroadcastListener 启动 Redis 广播监听器
func StartRedisBroadcastListener(ctx context.Context) {
	log.Println("Redis Pub/Sub 监听器已启动")
	defer log.Println("Redis Pub/Sub 监听器已停止")

	pubsub := db.SubscribeBroadcast(ctx)
	if pubsub == nil {
		return
	}
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			// 转发到 SSE Broker
			select {
			case sseBroker.Message <- msg.Payload:
			default:
				// Broker 阻塞，跳过此消息
			}
		}
	}
}

// startSSEBroker 启动 SSE Broker
func startSSEBroker() {
	for {
		select {
		case s := <-sseBroker.NewClients:
			sseBroker.mu.Lock()
			sseBroker.Clients[s] = true
			sseBroker.mu.Unlock()
		case s := <-sseBroker.ClosedClients:
			sseBroker.mu.Lock()
			delete(sseBroker.Clients, s)
			sseBroker.mu.Unlock()
			close(s)
		case msg := <-sseBroker.Message:
			sseBroker.mu.RLock()
			for s := range sseBroker.Clients {
				select {
				case s <- msg:
				default:
					// 客户端阻塞，移除
					go func(client chan string) {
						sseBroker.mu.Lock()
						delete(sseBroker.Clients, client)
						sseBroker.mu.Unlock()
						close(client)
					}(s)
				}
			}
			sseBroker.mu.RUnlock()
		}
	}
}

// GetSSEStream 获取 SSE 流
func GetSSEStream(w io.Writer, clientChan chan string) bool {
	if msg, ok := <-clientChan; ok {
		fmt.Fprintf(w, "data: %s\n\n", msg)
		return true
	}
	return false
}

// RegisterSSEClient 注册 SSE 客户端
func RegisterSSEClient() chan string {
	clientChan := make(chan string)
	sseBroker.NewClients <- clientChan
	return clientChan
}

// UnregisterSSEClient 注销 SSE 客户端
func UnregisterSSEClient(clientChan chan string) {
	sseBroker.ClosedClients <- clientChan
}

// ReloadWireGuard 重载 WireGuard 配置
func ReloadWireGuard(confName string) error {
	wgQuickPath := "/usr/bin/wg-quick"
	wgPath := "/usr/bin/wg"

	if _, err := os.Stat(wgQuickPath); os.IsNotExist(err) {
		wgQuickPath = "wg-quick"
	}
	if _, err := os.Stat(wgPath); os.IsNotExist(err) {
		wgPath = "wg"
	}

	cmdStrip := exec.Command(wgQuickPath, "strip", "/etc/wireguard/"+confName+".conf")
	configData, err := cmdStrip.Output()
	if err != nil {
		return fmt.Errorf("strip failed: %v", err)
	}

	cmdSync := exec.Command(wgPath, "syncconf", confName, "/ dev/stdin")
	// Fix: /dev/stdin argument
	cmdSync = exec.Command(wgPath, "syncconf", confName, "/dev/stdin")
	
	stdin, err := cmdSync.StdinPipe()
	if err != nil {
		return err
	}
	
	go func() {
		defer stdin.Close()
		stdin.Write(configData)
	}()

	if output, err := cmdSync.CombinedOutput(); err != nil {
		return fmt.Errorf("syncconf failed: %v, output: %s", err, string(output))
	}

	log.Printf("WireGuard (%s) 热重载成功", confName)
	return nil
}

// GeneratePeerKeys 生成客户端密钥
func GeneratePeerKeys() (string, string, string, error) {
	pKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", "", err
	}
	pubKey := pKey.PublicKey()
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		return "", "", "", err
	}
	return pKey.String(), pubKey.String(), presharedKey.String(), nil
}

// IsValidConfigName 验证配置名
func IsValidConfigName(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return validName.MatchString(name)
}

// SuggestIP 建议 IP
func SuggestIP(confName string) (string, error) {
	if confName == "" {
		confName = "wg0"
	}

	path := fmt.Sprintf("/etc/wireguard/%s.conf", confName)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	serverIPStr := ""
	lines := strings.Split(string(content), "\n")
	reAddr := regexp.MustCompile(`(?i)^\s*Address\s*=\s*([0-9.]+)(/[0-9]+)?`)

	usedIPs := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := reAddr.FindStringSubmatch(line); len(matches) > 1 {
			if serverIPStr == "" && strings.Contains(matches[1], ".") {
				serverIPStr = matches[1]
				usedIPs[matches[1]] = true
			}
		}
		if strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "allowedips") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				ips := strings.Split(parts[1], ",")
				for _, ipCidr := range ips {
					if ip, _, err := net.ParseCIDR(strings.TrimSpace(ipCidr)); err == nil {
						usedIPs[ip.String()] = true
					}
				}
			}
		}
	}

	if serverIPStr == "" {
		serverIPStr = "10.0.0.1"
	}

	ip := net.ParseIP(serverIPStr)
	if ip == nil {
		ip = net.ParseIP("10.0.0.1")
	}
	ip = ip.To4()

	baseIP := ip.Mask(net.CIDRMask(24, 32))
	suggested := ""
	for i := 2; i < 255; i++ {
		candidate := net.IPv4(baseIP[0], baseIP[1], baseIP[2], byte(i))
		candidateStr := candidate.String()
		if !usedIPs[candidateStr] {
			suggested = candidateStr + "/32"
			break
		}
	}

	if suggested == "" {
		return "", fmt.Errorf("该网段 IP 已耗尽")
	}

	return suggested, nil
}

// GenerateAnalysisReport 生成分析报告
func GenerateAnalysisReport(ctx context.Context, days int) (*models.AnalysisReport, error) {
	startTime := time.Now().AddDate(0, 0, -days).Unix()

	// 1. 获取基础统计
	rows, err := db.GetAnalysisDataQuery(ctx, startTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	peerStats := make(map[string]*models.PeerAnalysis)
	for rows.Next() {
		var pk string
		var count int
		var onlineCount int
		var rxSum, txSum float64
		var lastSeen int64
		if err := rows.Scan(&pk, &count, &onlineCount, &rxSum, &txSum, &lastSeen); err != nil {
			continue
		}

		uptime := 0.0
		if count > 0 {
			uptime = float64(onlineCount) / float64(count) * 100
		}

		// 计算健康分
		score := 100
		if uptime < 90 {
			score -= 20
		} else if uptime < 99 {
			score -= 5
		}
		if time.Now().Unix()-lastSeen > 86400*3 { // 3天未见
			score -= 30
		}

		peerStats[pk] = &models.PeerAnalysis{
			PublicKey:    pk,
			TotalRx:      int64(rxSum),
			TotalTx:      int64(txSum),
			Uptime:       uptime,
			HealthScore:  score,
			LastSeenTime: lastSeen,
		}
	}

	// 2. 填充别名
	aliases, _ := db.GetAliases()
	
	// 计算转换因子 (Mbps * 1e6 / 8 * Interval)
	byteFactor := config.MegabitsPerSecond / config.BitsPerByte * config.CollectInterval.Seconds()

	var peers []models.PeerAnalysis
	for pk, stat := range peerStats {
		stat.Alias = aliases[pk]
		// 修正：将累加的速率转换为字节数
		stat.TotalRx = int64(float64(stat.TotalRx) * byteFactor)
		stat.TotalTx = int64(float64(stat.TotalTx) * byteFactor)
		peers = append(peers, *stat)
	}

	// 3. 排序 (按流量倒序)
	sort.Slice(peers, func(i, j int) bool {
		return (peers[i].TotalRx + peers[i].TotalTx) > (peers[j].TotalRx + peers[j].TotalTx)
	})

	// 4. 获取每小时趋势
	hRows, err := db.GetHourlyProfileQuery(ctx, startTime)
	var hourly []models.ActivityPoint
	if err == nil {
		defer hRows.Close()
		var lastH int64
		for hRows.Next() {
			var ts int64
			var sum float64
			if err := hRows.Scan(&ts, &sum); err == nil {
				h := int((ts / 3600) % 24)
				// 简单聚合
				if ts/3600 != lastH {
					// 修正：将速率和转换为字节
					// 这里 sum 是该小时内所有记录的 rx_rate+tx_rate 之和
					// 大致估算：sum * byteFactor
					byteFactor := config.MegabitsPerSecond / config.BitsPerByte * config.CollectInterval.Seconds()
					hourly = append(hourly, models.ActivityPoint{
						Hour:  h,
						RxSum: sum * byteFactor, 
					})
					lastH = ts / 3600
				}
			}
		}
	}

	report := &models.AnalysisReport{
		Peers:         peers,
		HourlyProfile: hourly,
	}

	// 缓存结果
	db.SetCache(ctx, "wg:cache:analysis:"+strconv.Itoa(days), report, config.CacheTTL)

	return report, nil
}

// GetPeerHistory 获取单个 Peer 的历史数据
func GetPeerHistory(pk string, period string) (map[int64]interface{}, error) {
	now := time.Now().Unix()
	var duration, step int64
	switch period {
	case "realtime":
		duration, step = 1800, 10
	case "1h":
		duration, step = 3600, 30
	case "24h":
		duration, step = 86400, 600
	case "7d":
		duration, step = 604800, 3600
	default:
		duration, step = 1800, 10
	}
	startTime := now - duration

	rows, err := db.GetPeerHistoryQuery(pk, startTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type bucket struct {
		rx, tx float64
		count  int
	}
	buckets := make(map[int64]*bucket)
	for rows.Next() {
		var ts int64
		var rx, tx float64
		if err := rows.Scan(&ts, &rx, &tx); err != nil {
			continue
		}
		// 聚合
		key := (ts / step) * step
		if _, ok := buckets[key]; !ok {
			buckets[key] = &bucket{}
		}
		buckets[key].rx += rx
		buckets[key].tx += tx
		buckets[key].count++
	}

	// 转换为前端格式
	// 前端图表通常需要一个有序的数组，或者 map
	// 这里返回 map，让 handler 处理成 json
	result := make(map[int64]interface{})
	for k, v := range buckets {
		if v.count > 0 {
			result[k] = map[string]interface{}{
				"rx": v.rx / float64(v.count),
				"tx": v.tx / float64(v.count),
			}
		}
	}
	return result, nil
}

// GetGlobalTrafficChart 获取全局流量图表数据
func GetGlobalTrafficChart(period string) (map[int64]interface{}, error) {
	now := time.Now().Unix()
	var duration, step int64
	switch period {
	case "realtime":
		duration, step = 1800, 10
	case "1h":
		duration, step = 3600, 30
	case "24h":
		duration, step = 86400, 600
	case "7d":
		duration, step = 604800, 3600
	default:
		duration, step = 1800, 10
	}
	startTime := now - duration

	rows, err := db.GetTrafficChartDataQuery(startTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type bucket struct {
		rx, tx float64
		count  int
	}
	buckets := make(map[int64]*bucket)
	for rows.Next() {
		var ts int64
		var rx, tx float64
		if err := rows.Scan(&ts, &rx, &tx); err != nil {
			continue
		}
		// 聚合 (Database already groups by timestamp, but we might need to aligns to step)
		// For simplicity, assumed DB returns aligned or we align here
		key := (ts / step) * step
		if _, ok := buckets[key]; !ok {
			buckets[key] = &bucket{}
		}
		buckets[key].rx += rx
		buckets[key].tx += tx
		buckets[key].count++ // Actually DB uses SUM, so count is 1 per row group if aligned
	}

	result := make(map[int64]interface{})
	for k, v := range buckets {
		// 修正：求平均速率
		if v.count > 0 {
			result[k] = map[string]interface{}{
				"rx": v.rx / float64(v.count),
				"tx": v.tx / float64(v.count),
			}
		}
	}
	return result, nil
}

// GetPeerAccessLogs 获取 Peer 访问日志
func GetPeerAccessLogs(pk string) ([]models.ProcessedLog, error) {
	// 获取最近 24 小时的日志
	since := time.Now().Add(-24 * time.Hour).Unix()
	rows, err := db.GetAccessLogsQuery(pk, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.ProcessedLog
	for rows.Next() {
		var l models.ProcessedLog
		if err := rows.Scan(&l.Timestamp, &l.Endpoint, &l.RxBytes, &l.TxBytes); err != nil {
			continue
		}
		l.PublicKey = pk
		logs = append(logs, l)
	}
	return logs, nil
}

// RemovePeer 删除 Peer
func RemovePeer(publicKey string) error {
	// 1. 从 WG 接口移除
	cmd := exec.Command("wg", "set", config.WGInterface, "peer", publicKey, "remove")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg remove failed: %v", err)
	}

	// 2. 从配置文件移除 (可选，较复杂，涉及解析 Conf 文件)
	// 简单做法：仅从运行时移除，保留配置或手动修改配置
	// 进阶做法：读取配置文件，正则匹配删除

	// 3. 删除别名
	return db.DeleteAlias(publicKey)
}

// UpdateAlias 更新别名
func UpdateAlias(publicKey, alias string) error {
	return db.SaveAlias(publicKey, alias)
}

// InitGeoIP 初始化 GeoIP
func InitGeoIP() {
	if _, err := os.Stat(config.GeoCityPath); err == nil {
		if g, err := geoip2.Open(config.GeoCityPath); err == nil {
			geoCity = g
			log.Println("GeoIP City 数据库已加载")
		}
	}
	if _, err := os.Stat(config.GeoASNPath); err == nil {
		if g, err := geoip2.Open(config.GeoASNPath); err == nil {
			geoASN = g
			log.Println("GeoIP ASN 数据库已加载")
		}
	}
}

// LookupIP 查询 IP 信息
func LookupIP(ipStr string) map[string]string {
	res := make(map[string]string)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return res
	}

	if geoCity != nil {
		if record, err := geoCity.City(ip); err == nil {
			res["city"] = record.City.Names["zh-CN"]
			if res["city"] == "" {
				res["city"] = record.City.Names["en"]
			}
			res["country"] = record.Country.Names["zh-CN"]
			if res["country"] == "" {
				res["country"] = record.Country.Names["en"]
			}
			res["iso_code"] = record.Country.IsoCode
		}
	}

	if geoASN != nil {
		if record, err := geoASN.ASN(ip); err == nil {
			res["asn"] = record.AutonomousSystemOrganization
		}
	}
	return res
}
