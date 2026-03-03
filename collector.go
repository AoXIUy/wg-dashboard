package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// ================= 系统信息采集 =================

// collectSystemInfo 采集 CPU、内存、温度、主机信息
func collectSystemInfo() SystemInfo {
	var sys SystemInfo

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

// ================= Peer 数据采集 =================

// collectPeersData 从 WireGuard 内核读取所有 Peer 状态，合并 Redis/别名缓存后返回
func collectPeersData() ([]PeerData, string, int, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, "", 0, fmt.Errorf("创建 WireGuard 客户端失败: %w", err)
	}
	defer client.Close()

	device, err := client.Device(WGInterface)
	if err != nil {
		return nil, "", 0, fmt.Errorf("获取设备信息失败: %w", err)
	}

	// 刷新别名缓存（如果过期则后台异步刷新）
	if aliasCache.NeedsRefresh() {
		go aliasCache.Refresh(context.Background())
	}

	// 批量获取 Redis 状态
	var redisCmds map[string]*redis.StringStringMapCmd
	if redisEnabled {
		pipe := rdb.Pipeline()
		redisCmds = make(map[string]*redis.StringStringMapCmd)
		for _, p := range device.Peers {
			key := fmt.Sprintf("wg:peer:state:%s", p.PublicKey.String())
			redisCmds[p.PublicKey.String()] = pipe.HGetAll(context.Background(), key)
		}
		if _, err := pipe.Exec(context.Background()); err != nil {
			logger.Printf("Redis Pipeline 执行失败: %v", err)
			metrics.IncRedisErrors()
		}
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
		var lastSeenTime int64

		// 从 Redis 获取实时状态
		if redisEnabled && redisCmds != nil {
			if val, err := redisCmds[pk].Result(); err == nil && len(val) > 0 {
				rxRate, _ = strconv.ParseFloat(val["rx_rate"], 64)
				txRate, _ = strconv.ParseFloat(val["tx_rate"], 64)
				onlineInt, _ := strconv.Atoi(val["is_online"])
				isOnline = onlineInt == 1
				lastSeenTime, _ = strconv.ParseInt(val["last_seen"], 10, 64)
			}
		}

		// 回退到握手时间判断在线状态
		if !isOnline && !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < OnlineThreshold {
			isOnline = true
		}

		alias, _ := aliasCache.Get(pk)

		var latestHandshake int64
		if !p.LastHandshakeTime.IsZero() {
			latestHandshake = p.LastHandshakeTime.Unix()
		}

		peers = append(peers, PeerData{
			PublicKey:       pk,
			AllowedIPs:      ips,
			Endpoint:        ep,
			LastHandshake:   p.LastHandshakeTime,
			LatestHandshake: latestHandshake,
			ReceiveBytes:    p.ReceiveBytes,
			TransmitBytes:   p.TransmitBytes,
			Alias:           alias,
			RxRate:          rxRate,
			TxRate:          txRate,
			IsOnline:        isOnline,
			Latency:         getPeerLatency(pk),
			LastSeenTime:    lastSeenTime,
			Enabled:         aliasCache.GetEnabled(pk),
		})
	}

	// 补充被内核层禁用的 peer（存在 peer_configs 表但已从 WireGuard 移除）
	if db != nil {
		disCtx, disCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer disCancel()

		rows, dbErr := db.QueryContext(disCtx, "SELECT public_key, peer_block FROM peer_configs")
		if dbErr == nil {
			defer rows.Close()
			existingKeys := make(map[string]bool, len(peers))
			for _, p := range peers {
				existingKeys[p.PublicKey] = true
			}

			for rows.Next() {
				var dpk, dblock string
				if err := rows.Scan(&dpk, &dblock); err != nil {
					continue
				}
				if existingKeys[dpk] {
					continue
				}
				alias, _ := aliasCache.Get(dpk)
				allowedIPs := parsePeerBlockIPs(dblock)
				peers = append(peers, PeerData{
					PublicKey:  dpk,
					AllowedIPs: allowedIPs,
					Endpoint:   "未连接",
					Alias:      alias,
					IsOnline:   false,
					Enabled:    false, // 明确标记为禁用
				})
			}
		}
	}

	// 排序：启用 > 禁用；在线 > 离线；速率降序；握手时间降序
	sort.Slice(peers, func(i, j int) bool {
		ei, ej := peers[i].Enabled, peers[j].Enabled
		if ei != ej {
			return ei
		}
		if peers[i].IsOnline != peers[j].IsOnline {
			return peers[i].IsOnline
		}
		rateI := peers[i].RxRate + peers[i].TxRate
		rateJ := peers[j].RxRate + peers[j].TxRate
		if rateI != rateJ {
			return rateI > rateJ
		}
		return peers[i].LastHandshake.After(peers[j].LastHandshake)
	})

	return peers, device.PublicKey.String(), device.ListenPort, nil
}

// parsePeerBlockIPs 从 peer_block 文本中解析 AllowedIPs 字段
func parsePeerBlockIPs(block string) []string {
	var ips []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "allowedips") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				for _, ip := range strings.Split(parts[1], ",") {
					if s := strings.TrimSpace(ip); s != "" {
						ips = append(ips, s)
					}
				}
			}
			break
		}
	}
	return ips
}

// ================= 数据采集 Pipeline =================

// startCollector 定时从 WireGuard 内核采集快照并推送到 rawChan
func startCollector(ctx context.Context, out chan<- RawSnapshot) {
	logger.Println("采集器已启动")
	defer logger.Println("采集器已停止")

	var client *wgctrl.Client
	var err error

	reconnect := func() error {
		if client != nil {
			client.Close()
		}
		client, err = wgctrl.New()
		if err != nil {
			logger.Printf("WireGuard 连接失败: %v", err)
			return err
		}
		return nil
	}

	if err := reconnect(); err != nil {
		logger.Printf("初始连接失败，将在后续重试")
	}
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	ticker := time.NewTicker(CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(out)
			return
		case <-ticker.C:
			if client == nil {
				if err := reconnect(); err != nil {
					continue
				}
			}

			device, err := client.Device(WGInterface)
			if err != nil {
				logger.Printf("获取设备信息失败: %v，尝试重连", err)
				reconnect()
				continue
			}

			select {
			case out <- RawSnapshot{Timestamp: time.Now(), Peers: device.Peers}:
			case <-ctx.Done():
				return
			default:
				logger.Println("警告: 采集通道已满，跳过此快照")
			}
		}
	}
}

// startProcessor 从 rawChan 读取快照并计算速率增量
func startProcessor(ctx context.Context, in <-chan RawSnapshot) {
	logger.Println("处理器已启动")
	defer logger.Println("处理器已停止")

	stateMap := make(map[string]*PeerState)

	for {
		select {
		case <-ctx.Done():
			return
		case snap, ok := <-in:
			if !ok {
				return
			}
			processSnapshot(ctx, snap, stateMap)
		}
	}
}

// processSnapshot 处理单个快照：计算速率、写入缓冲、更新 Redis
func processSnapshot(ctx context.Context, snap RawSnapshot, stateMap map[string]*PeerState) {
	var pipe redis.Pipeliner
	if redisEnabled {
		pipe = rdb.Pipeline()
	}

	for _, p := range snap.Peers {
		pk := p.PublicKey.String()
		state, exists := stateMap[pk]

		if !exists {
			state = &PeerState{
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
				rxRate = float64(p.ReceiveBytes-state.LastRx) * BitsPerByte / timeDiff / MegabitsPerSecond
			}
			if p.TransmitBytes >= state.LastTx {
				txRate = float64(p.TransmitBytes-state.LastTx) * BitsPerByte / timeDiff / MegabitsPerSecond
			}
		}

		isOnline := !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < OnlineThreshold

		state.LastRx = p.ReceiveBytes
		state.LastTx = p.TransmitBytes
		state.LastSeen = snap.Timestamp

		epStr := ""
		if p.Endpoint != nil {
			epStr = p.Endpoint.IP.String()
		}

		logEntry := ProcessedLog{
			Timestamp: snap.Timestamp.Unix(),
			PublicKey: pk,
			Endpoint:  epStr,
			RxBytes:   p.ReceiveBytes,
			TxBytes:   p.TransmitBytes,
			RxRate:    rxRate,
			TxRate:    txRate,
			IsOnline:  isOnline,
		}

		// 写入内存缓冲，满时立即异步刷库
		shouldFlush := trafficBuffer.Add(logEntry)
		metrics.IncProcessed()

		if shouldFlush {
			go func() {
				batch := trafficBuffer.Flush()
				if batch != nil {
					flushMySQL(batch)
				}
			}()
		}

		// 更新 Redis 状态（批量 Pipeline）
		if redisEnabled && pipe != nil {
			updateRedisState(pipe, ctx, pk, rxRate, txRate, isOnline, epStr, snap.Timestamp.Unix())
		}
	}

	// 执行 Redis Pipeline 并广播更新
	if redisEnabled && pipe != nil {
		if _, err := pipe.Exec(ctx); err != nil {
			logger.Printf("Redis Pipeline 执行失败: %v", err)
			metrics.IncRedisErrors()
		} else {
			broadcastUpdate(ctx)
		}
	}
}

// updateRedisState 将 Peer 实时状态写入 Redis Hash（5 分钟 TTL）
func updateRedisState(pipe redis.Pipeliner, ctx context.Context, pk string, rxRate, txRate float64, isOnline bool, endpoint string, timestamp int64) {
	key := fmt.Sprintf("wg:peer:state:%s", pk)
	onlineVal := 0
	if isOnline {
		onlineVal = 1
	}

	pipe.HSet(ctx, key, map[string]interface{}{
		"rx_rate":   rxRate,
		"tx_rate":   txRate,
		"is_online": onlineVal,
		"endpoint":  endpoint,
		"last_seen": timestamp,
	})
	pipe.Expire(ctx, key, 5*time.Minute)
}

// broadcastUpdate 收集当前全量数据并推送给所有 SSE 客户端（或 Redis Pub/Sub）
func broadcastUpdate(ctx context.Context) {
	peers, _, _, err := collectPeersData()
	if err != nil {
		logger.Printf("收集 Peer 数据失败: %v", err)
		return
	}

	update := DashboardUpdate{
		Peers:     peers,
		System:    collectSystemInfo(),
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(update)
	if err != nil {
		logger.Printf("序列化更新数据失败: %v", err)
		return
	}

	if redisEnabled {
		if err := rdb.Publish(ctx, "wg:channel:broadcast", string(jsonData)).Err(); err != nil {
			logger.Printf("Redis 发布失败: %v", err)
			metrics.IncRedisErrors()
		}
	} else {
		select {
		case sseBroker.Message <- string(jsonData):
		default:
		}
	}
}

// ================= Ping 监控 =================

// startPinger 定时对所有在线 Peer 的 AllowedIP 进行 Ping，更新延迟缓存
func startPinger(ctx context.Context) {
	logger.Println("Ping 监控已启动")
	defer logger.Println("Ping 监控已停止")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if db == nil {
				continue
			}

			peers, _, _, err := collectPeersData()
			if err != nil {
				logger.Printf("获取 Peer 列表失败: %v", err)
				continue
			}

			var wg sync.WaitGroup
			semaphore := make(chan struct{}, 10) // 最多 10 个并发 Ping

			for _, p := range peers {
				if !p.IsOnline || len(p.AllowedIPs) == 0 {
					latencyCache.Delete(p.PublicKey)
					continue
				}

				targetIP := strings.Split(p.AllowedIPs[0], "/")[0]
				if strings.Contains(targetIP, ":") {
					continue // 跳过 IPv6
				}

				wg.Add(1)
				go func(pk, ip string) {
					defer wg.Done()

					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					latency := pingHost(ip)
					if latency > 0 {
						latencyCache.Set(pk, fmt.Sprintf("%dms", latency))
					} else {
						latencyCache.Delete(pk)
					}
				}(p.PublicKey, targetIP)
			}

			wg.Wait()
		}
	}
}

// pingHost 对指定 IP 执行单次 Ping，返回延迟毫秒数（失败返回 0）
func pingHost(ip string) int64 {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return 0
	}
	return time.Since(start).Milliseconds()
}

// getPeerLatency 供其他模块调用，获取 Peer 当前延迟字符串
func getPeerLatency(pk string) string {
	if latencyCache == nil {
		return ""
	}
	return latencyCache.Get(pk)
}
