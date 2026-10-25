package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMockExecutor_BasicAndTraffic(t *testing.T) {
	tmpDir := filepath.Join(SandboxConfigsDir, "test_mock")
	_ = os.RemoveAll(tmpDir)
	defer os.RemoveAll(tmpDir)

	mock, err := NewMockExecutor(tmpDir, "wg0")
	if err != nil {
		t.Fatalf("NewMockExecutor failed: %v", err)
	}

	if !mock.IsMock() {
		t.Errorf("expected IsMock() to be true")
	}

	// 验证获取设备
	dev1, err := mock.GetDevice("wg0")
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if len(dev1.Peers) == 0 {
		t.Fatalf("expected mock peers, got 0")
	}

	// 记录初始流量
	var initRx int64
	for _, p := range dev1.Peers {
		initRx += p.ReceiveBytes
	}

	// 再次获取设备，在线节点的流量应该增长
	dev2, err := mock.GetDevice("wg0")
	if err != nil {
		t.Fatalf("second GetDevice failed: %v", err)
	}
	var newRx int64
	for _, p := range dev2.Peers {
		newRx += p.ReceiveBytes
	}

	if newRx <= initRx {
		t.Errorf("expected traffic to grow in mock mode, initRx=%d, newRx=%d", initRx, newRx)
	}
}

func TestMockExecutor_ConfigsAndReload(t *testing.T) {
	tmpDir := filepath.Join(SandboxConfigsDir, "test_configs")
	_ = os.RemoveAll(tmpDir)
	defer os.RemoveAll(tmpDir)

	mock, err := NewMockExecutor(tmpDir, "wg0")
	if err != nil {
		t.Fatalf("NewMockExecutor failed: %v", err)
	}

	// 验证配置列表
	configs, err := mock.ListConfigs()
	if err != nil {
		t.Fatalf("ListConfigs failed: %v", err)
	}
	if len(configs) != 1 || configs[0] != "wg0" {
		t.Fatalf("expected ['wg0'], got %v", configs)
	}

	// 读取配置
	data, err := mock.ReadConfigFile("wg0")
	if err != nil {
		t.Fatalf("ReadConfigFile failed: %v", err)
	}
	if !strings.Contains(string(data), "[Interface]") {
		t.Errorf("expected [Interface] in config, got:\n%s", string(data))
	}

	// 生成一个新 peer 并追加到配置文件
	newKey, _ := wgtypes.GeneratePrivateKey()
	newPub := newKey.PublicKey()
	peerBlock := "\n[Peer]\nPublicKey = " + newPub.String() + "\nAllowedIPs = 10.0.0.50/32\n"

	newData := append(data, []byte(peerBlock)...)
	if err := mock.WriteConfigFile("wg0", newData); err != nil {
		t.Fatalf("WriteConfigFile failed: %v", err)
	}

	// 重载
	if err := mock.ReloadWireGuard("wg0"); err != nil {
		t.Fatalf("ReloadWireGuard failed: %v", err)
	}

	// 验证新 peer 已进入内存
	dev, err := mock.GetDevice("wg0")
	if err != nil {
		t.Fatalf("GetDevice after reload failed: %v", err)
	}

	found := false
	for _, p := range dev.Peers {
		if p.PublicKey.String() == newPub.String() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("new peer %s not found in mock device after reload", newPub.String())
	}
}

func TestMockExecutor_PingAndTraceroute(t *testing.T) {
	mock, err := NewMockExecutor(SandboxConfigsDir, "wg0")
	if err != nil {
		t.Fatalf("NewMockExecutor failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Ping 正常地址
	pingRes, err := mock.Ping(ctx, "10.0.0.2", 2)
	if err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	if !pingRes.IsAlive || pingRes.PacketsReceived != 2 {
		t.Errorf("expected alive ping with 2 packets, got: %+v", pingRes)
	}

	// Ping 特殊离线地址
	pingOffline, err := mock.Ping(ctx, "192.0.2.254", 2)
	if err != nil {
		t.Fatalf("Ping offline failed: %v", err)
	}
	if pingOffline.IsAlive || pingOffline.PacketLoss != 100.0 {
		t.Errorf("expected offline ping with 100%% loss, got: %+v", pingOffline)
	}

	// Traceroute
	traceRes, err := mock.Traceroute(ctx, "10.0.0.2", 15)
	if err != nil {
		t.Fatalf("Traceroute failed: %v", err)
	}
	if len(traceRes.Hops) == 0 {
		t.Errorf("expected simulated hops, got 0")
	}
}
