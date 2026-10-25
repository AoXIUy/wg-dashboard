package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardExecutor 定义对 WireGuard 内核、配置文件和网络诊断的统一抽象接口
type WireGuardExecutor interface {
	// GetDevice 获取指定接口的 WireGuard 设备状态（含全部 Peer）
	GetDevice(iface string) (*wgtypes.Device, error)

	// ListConfigs 列出所有可用的 WireGuard 配置文件名（不含 .conf 后缀）
	ListConfigs() ([]string, error)

	// ReadConfigFile 读取指定配置文件的完整文本内容
	ReadConfigFile(confName string) ([]byte, error)

	// WriteConfigFile 写入指定配置文件的完整文本内容（原子写入）
	WriteConfigFile(confName string, data []byte) error

	// ReloadWireGuard 热重载指定接口配置 (如 wg-quick strip + wg syncconf)
	ReloadWireGuard(confName string) error

	// Ping 执行 Ping 探测并返回结构化结果
	Ping(ctx context.Context, ip string, count int) (*PingResponse, error)

	// Traceroute 执行路由追踪探测并返回结构化结果
	Traceroute(ctx context.Context, ip string, maxHops int) (*TracerouteResponse, error)

	// IsMock 返回当前是否为 Mock 沙盒模式
	IsMock() bool

	// ConfigDir 返回当前配置文件所在目录
	ConfigDir() string
}

const (
	SandboxDataDir    = "./.sandbox_data"
	SandboxConfigsDir = "./.sandbox_data/configs"
	SandboxBackupsDir = "./.sandbox_data/backups"
)

// InitExecutor 初始化全局 WireGuardExecutor
func InitExecutor() {
	// 确保沙盒目录始终存在
	_ = os.MkdirAll(SandboxDataDir, 0755)
	_ = os.MkdirAll(SandboxConfigsDir, 0755)
	_ = os.MkdirAll(SandboxBackupsDir, 0755)

	// 判断是否启用 Mock
	// 1. 显式指定 -mock 或环境变量 WG_MOCK=true/1
	// 2. 非 Linux 系统（如 Windows/macOS）默认回退为 Mock 模式，确保开发与测试环境宿主机安全
	// 3. 非 root 权限且无特权环境
	if IsMockMode || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		if !IsMockMode {
			logger.Println("[沙盒隔离] 检测到非 Linux Root 环境，自动激活 MockExecutor 沙盒模拟层以保护宿主机")
			IsMockMode = true
		} else {
			logger.Println("[沙盒隔离] -mock 参数生效，已激活 MockExecutor 沙盒模式")
		}

		if WGConfigDir == "" {
			WGConfigDir = SandboxConfigsDir
		}

		mockExec, err := NewMockExecutor(WGConfigDir, WGInterface)
		if err != nil {
			logger.Fatalf("初始化 MockExecutor 失败: %v", err)
		}
		wgExecutor = mockExec
	} else {
		if WGConfigDir == "" {
			WGConfigDir = "/etc/wireguard"
		}
		logger.Printf("[宿主机模式] 使用真实 WireGuard 执行层，配置目录: %s", WGConfigDir)
		wgExecutor = NewRealExecutor(WGConfigDir)
	}
}

// resolveConfigPath 根据配置名返回绝对/规范化文件路径
func resolveConfigPath(dir, confName string) string {
	return filepath.Join(dir, fmt.Sprintf("%s.conf", confName))
}
