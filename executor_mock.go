package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MockExecutor 沙盒模式下的 WireGuard 执行器，所有操作在内存与沙盒目录中模拟，绝不触碰宿主机
type MockExecutor struct {
	mu         sync.RWMutex
	configDir  string
	ifaceName  string
	serverPriv wgtypes.Key
	serverPub  wgtypes.Key
	listenPort int
	peers      map[string]*mockPeerState
}

type mockPeerState struct {
	PublicKey         wgtypes.Key
	PresharedKey      wgtypes.Key
	Endpoint          *net.UDPAddr
	AllowedIPs        []net.IPNet
	LastHandshakeTime time.Time
	ReceiveBytes      int64
	TransmitBytes     int64
	IsOnline          bool
	LatencyMs         int64
}

// NewMockExecutor 创建并初始化 MockExecutor
func NewMockExecutor(configDir, ifaceName string) (*MockExecutor, error) {
	if configDir == "" {
		configDir = SandboxConfigsDir
	}
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("创建 Mock 配置目录失败: %w", err)
	}

	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("生成模拟服务端私钥失败: %w", err)
	}
	serverPub := serverPriv.PublicKey()

	m := &MockExecutor{
		configDir:  configDir,
		ifaceName:  ifaceName,
		serverPriv: serverPriv,
		serverPub:  serverPub,
		listenPort: 51820,
		peers:      make(map[string]*mockPeerState),
	}

	// 初始化初始模拟 Peers
	m.initMockPeers()

	// 确保 sample 配置文件存在
	if err := m.ensureSampleConfig(ifaceName); err != nil {
		return nil, fmt.Errorf("生成初始沙盒配置失败: %w", err)
	}

	return m, nil
}

func (m *MockExecutor) IsMock() bool {
	return true
}

func (m *MockExecutor) ConfigDir() string {
	return m.configDir
}

// initMockPeers 初始化一组具有不同在线状态和特征的 Peer
func (m *MockExecutor) initMockPeers() {
	now := time.Now()

	// Peer 1: Alice - 高流量活跃在线设备
	pk1, _ := wgtypes.GeneratePrivateKey()
	psk1, _ := wgtypes.GenerateKey()
	pub1 := pk1.PublicKey()
	_, ipnet1, _ := net.ParseCIDR("10.0.0.2/32")
	m.peers[pub1.String()] = &mockPeerState{
		PublicKey:         pub1,
		PresharedKey:      psk1,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("198.51.100.22"), Port: 51820},
		AllowedIPs:        []net.IPNet{*ipnet1},
		LastHandshakeTime: now.Add(-15 * time.Second),
		ReceiveBytes:      1024 * 1024 * 128,  // 128 MB
		TransmitBytes:     1024 * 1024 * 1024, // 1 GB
		IsOnline:          true,
		LatencyMs:         18,
	}

	// Peer 2: Bob - 手机设备，持续在线
	pk2, _ := wgtypes.GeneratePrivateKey()
	psk2, _ := wgtypes.GenerateKey()
	pub2 := pk2.PublicKey()
	_, ipnet2, _ := net.ParseCIDR("10.0.0.3/32")
	m.peers[pub2.String()] = &mockPeerState{
		PublicKey:         pub2,
		PresharedKey:      psk2,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("203.0.113.88"), Port: 42150},
		AllowedIPs:        []net.IPNet{*ipnet2},
		LastHandshakeTime: now.Add(-45 * time.Second),
		ReceiveBytes:      1024 * 1024 * 45,
		TransmitBytes:     1024 * 1024 * 68,
		IsOnline:          true,
		LatencyMs:         32,
	}

	// Peer 3: Charlie - 离线节点 (上次握手在 5 天前)
	pk3, _ := wgtypes.GeneratePrivateKey()
	psk3, _ := wgtypes.GenerateKey()
	pub3 := pk3.PublicKey()
	_, ipnet3, _ := net.ParseCIDR("10.0.0.4/32")
	m.peers[pub3.String()] = &mockPeerState{
		PublicKey:         pub3,
		PresharedKey:      psk3,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("192.0.2.14"), Port: 51820},
		AllowedIPs:        []net.IPNet{*ipnet3},
		LastHandshakeTime: now.Add(-5 * 24 * time.Hour),
		ReceiveBytes:      1024 * 1024 * 12,
		TransmitBytes:     1024 * 1024 * 8,
		IsOnline:          false,
		LatencyMs:         0,
	}

	// Peer 4: Edge Gateway - 稳定大吞吐设备
	pk4, _ := wgtypes.GeneratePrivateKey()
	psk4, _ := wgtypes.GenerateKey()
	pub4 := pk4.PublicKey()
	_, ipnet4, _ := net.ParseCIDR("10.0.0.5/32")
	m.peers[pub4.String()] = &mockPeerState{
		PublicKey:         pub4,
		PresharedKey:      psk4,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("198.51.100.99"), Port: 51820},
		AllowedIPs:        []net.IPNet{*ipnet4},
		LastHandshakeTime: now.Add(-5 * time.Second),
		ReceiveBytes:      1024 * 1024 * 512,
		TransmitBytes:     1024 * 1024 * 820,
		IsOnline:          true,
		LatencyMs:         12,
	}
}

// ensureSampleConfig 如果沙盒配置目录下不存在对应的 .conf 文件，则根据当前 mockPeers 生成一份完整合法的文件
func (m *MockExecutor) ensureSampleConfig(iface string) error {
	confPath := resolveConfigPath(m.configDir, iface)
	if _, err := os.Stat(confPath); err == nil {
		// 文件已存在，解析它并同步 peers
		return m.syncFromConfigFile(confPath)
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", m.serverPriv.String()))
	sb.WriteString("Address = 10.0.0.1/24\n")
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n\n", m.listenPort))

	mockNames := []string{"Alice-MacBook", "Bob-iPhone", "Charlie-Linux", "Edge-Gateway"}
	idx := 0
	for _, p := range m.peers {
		name := "Client"
		if idx < len(mockNames) {
			name = mockNames[idx]
		}
		idx++

		sb.WriteString(fmt.Sprintf("# Name: %s\n", name))
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.PublicKey.String()))
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", p.PresharedKey.String()))
		var ips []string
		for _, ip := range p.AllowedIPs {
			ips = append(ips, ip.String())
		}
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(ips, ", ")))
		if p.Endpoint != nil {
			sb.WriteString(fmt.Sprintf("Endpoint = %s\n", p.Endpoint.String()))
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(confPath, []byte(sb.String()), 0600)
}

// GetDevice 模拟 WireGuard 内核查询并动态增长在线 Peer 的流量
func (m *MockExecutor) GetDevice(iface string) (*wgtypes.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var wgPeers []wgtypes.Peer

	for _, p := range m.peers {
		// 如果在线，动态模拟随机流量增长 (15KB ~ 350KB)
		if p.IsOnline {
			rxIncr := int64(15000 + rand.Intn(300000))
			txIncr := int64(12000 + rand.Intn(250000))
			p.ReceiveBytes += rxIncr
			p.TransmitBytes += txIncr
			// 刷新握手时间保持在线
			if now.Sub(p.LastHandshakeTime) > 2*time.Minute {
				p.LastHandshakeTime = now.Add(-time.Duration(rand.Intn(40)) * time.Second)
			}
		}

		wgPeers = append(wgPeers, wgtypes.Peer{
			PublicKey:         p.PublicKey,
			PresharedKey:      p.PresharedKey,
			Endpoint:          p.Endpoint,
			AllowedIPs:        p.AllowedIPs,
			LastHandshakeTime: p.LastHandshakeTime,
			ReceiveBytes:      p.ReceiveBytes,
			TransmitBytes:     p.TransmitBytes,
		})
	}

	dev := &wgtypes.Device{
		Name:         iface,
		Type:         wgtypes.LinuxKernel,
		PublicKey:    m.serverPub,
		PrivateKey:   m.serverPriv,
		ListenPort:   m.listenPort,
		FirewallMark: 0,
		Peers:        wgPeers,
	}

	return dev, nil
}

// ListConfigs 列出沙盒配置目录下的所有 .conf 文件
func (m *MockExecutor) ListConfigs() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	files, err := filepath.Glob(filepath.Join(m.configDir, "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("无法扫描沙盒配置目录: %w", err)
	}

	var configs []string
	for _, f := range files {
		base := filepath.Base(f)
		configs = append(configs, strings.TrimSuffix(base, filepath.Ext(base)))
	}
	return configs, nil
}

// ReadConfigFile 读取沙盒配置文件
func (m *MockExecutor) ReadConfigFile(confName string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	path := resolveConfigPath(m.configDir, confName)
	return os.ReadFile(path)
}

// WriteConfigFile 原子替换沙盒配置文件
func (m *MockExecutor) WriteConfigFile(confName string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := resolveConfigPath(m.configDir, confName)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("写入沙盒临时配置文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("原子替换沙盒配置文件失败: %w", err)
	}
	return nil
}

// ReloadWireGuard 从沙盒配置文件重新加载 Peers 状态到内存 Mock 设备中
func (m *MockExecutor) ReloadWireGuard(confName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := resolveConfigPath(m.configDir, confName)
	return m.syncFromConfigFileLocked(path)
}

func (m *MockExecutor) syncFromConfigFile(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncFromConfigFileLocked(path)
}

// syncFromConfigFileLocked 从配置文本同步 peers
func (m *MockExecutor) syncFromConfigFileLocked(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	newPeers := make(map[string]*mockPeerState)

	var currentPubKey, currentPsk, currentAllowedIPs, currentEndpoint string

	commitPeer := func() {
		if currentPubKey != "" {
			key, err := wgtypes.ParseKey(currentPubKey)
			if err == nil {
				psk, _ := wgtypes.ParseKey(currentPsk)
				var allowedIPs []net.IPNet
				for _, ipStr := range strings.Split(currentAllowedIPs, ",") {
					ipStr = strings.TrimSpace(ipStr)
					if _, ipnet, err := net.ParseCIDR(ipStr); err == nil && ipnet != nil {
						allowedIPs = append(allowedIPs, *ipnet)
					}
				}

				var udpAddr *net.UDPAddr
				if currentEndpoint != "" {
					if addr, err := net.ResolveUDPAddr("udp", currentEndpoint); err == nil {
						udpAddr = addr
					}
				}

				// 保留已有 peer 的流量与握手记录，新增 peer 初始化默认值
				if existing, ok := m.peers[currentPubKey]; ok {
					existing.AllowedIPs = allowedIPs
					existing.Endpoint = udpAddr
					newPeers[currentPubKey] = existing
				} else {
					newPeers[currentPubKey] = &mockPeerState{
						PublicKey:         key,
						PresharedKey:      psk,
						Endpoint:          udpAddr,
						AllowedIPs:        allowedIPs,
						LastHandshakeTime: time.Now().Add(-10 * time.Second),
						ReceiveBytes:      1024 * 100,
						TransmitBytes:     1024 * 200,
						IsOnline:          true,
						LatencyMs:         24,
					}
				}
			}
		}
		currentPubKey = ""
		currentPsk = ""
		currentAllowedIPs = ""
		currentEndpoint = ""
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[Peer]") {
			commitPeer()
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) == 2 {
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := strings.TrimSpace(parts[1])
			switch k {
			case "publickey":
				currentPubKey = v
			case "presharedkey":
				currentPsk = v
			case "allowedips":
				currentAllowedIPs = v
			case "endpoint":
				currentEndpoint = v
			}
		}
	}
	commitPeer()

	m.peers = newPeers
	return nil
}

// Ping 在内存中模拟 Ping 探测
func (m *MockExecutor) Ping(ctx context.Context, ip string, count int) (*PingResponse, error) {
	if count <= 0 {
		count = 4
	}

	// 模拟短暂的响应耗时 (10ms ~ 30ms)
	select {
	case <-time.After(time.Duration(15+rand.Intn(20)) * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// 特殊离线与丢包测试 IP 模拟
	if ip == "192.0.2.254" || ip == "0.0.0.0" {
		return &PingResponse{
			Address:         ip,
			IsAlive:         false,
			PacketsSent:     count,
			PacketsReceived: 0,
			PacketLoss:      100.0,
		}, nil
	}
	if ip == "192.0.2.50" {
		recv := count / 2
		loss := float64(count-recv) / float64(count) * 100
		return &PingResponse{
			Address:         ip,
			IsAlive:         true,
			MinRtt:          20.0,
			AvgRtt:          35.0,
			MaxRtt:          50.0,
			Jitter:          15.0,
			PacketsSent:     count,
			PacketsReceived: recv,
			PacketLoss:      loss,
		}, nil
	}

	baseRtt := float64(12 + rand.Intn(25))
	jitter := float64(1 + rand.Intn(6))
	minRtt := baseRtt - jitter/2
	maxRtt := baseRtt + jitter/2
	if minRtt < 1 {
		minRtt = 1
	}

	return &PingResponse{
		Address:         ip,
		IsAlive:         true,
		MinRtt:          minRtt,
		AvgRtt:          baseRtt,
		MaxRtt:          maxRtt,
		Jitter:          jitter,
		PacketsSent:     count,
		PacketsReceived: count,
		PacketLoss:      0.0,
	}, nil
}

// Traceroute 在内存中模拟 Traceroute 探测
func (m *MockExecutor) Traceroute(ctx context.Context, ip string, maxHops int) (*TracerouteResponse, error) {
	if maxHops <= 0 || maxHops > 30 {
		maxHops = 15
	}

	select {
	case <-time.After(30 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	hops := []TracerouteHop{
		{
			Distance: 1,
			Address:  "10.0.0.1",
			MinRtt:   0.6,
			AvgRtt:   0.8,
			MaxRtt:   1.2,
		},
		{
			Distance: 2,
			Address:  "192.168.1.1",
			MinRtt:   1.8,
			AvgRtt:   2.2,
			MaxRtt:   3.1,
		},
		{
			Distance: 3,
			Address:  "203.0.113.1",
			MinRtt:   11.5,
			AvgRtt:   13.4,
			MaxRtt:   16.8,
		},
		{
			Distance: 4,
			Address:  ip,
			MinRtt:   22.1,
			AvgRtt:   25.3,
			MaxRtt:   29.7,
		},
	}

	var rawBuf bytes.Buffer
	rawBuf.WriteString(fmt.Sprintf("traceroute to %s, 30 hops max\n", ip))
	for _, h := range hops {
		rawBuf.WriteString(fmt.Sprintf("%2d  %s  %.3f ms  %.3f ms  %.3f ms\n", h.Distance, h.Address, h.MinRtt, h.AvgRtt, h.MaxRtt))
	}

	return &TracerouteResponse{
		Target:    ip,
		Hops:      hops,
		RawOutput: rawBuf.String(),
	}, nil
}
