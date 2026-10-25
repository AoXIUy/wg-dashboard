package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RealExecutor 宿主机真实 WireGuard 执行层，仅在 Linux root 且显式禁用 Mock 时使用
type RealExecutor struct {
	configDir string
}

func NewRealExecutor(configDir string) *RealExecutor {
	if configDir == "" {
		configDir = "/etc/wireguard"
	}
	return &RealExecutor{configDir: configDir}
}

func (r *RealExecutor) IsMock() bool {
	return false
}

func (r *RealExecutor) ConfigDir() string {
	return r.configDir
}

func (r *RealExecutor) GetDevice(iface string) (*wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("创建 WireGuard 客户端失败: %w", err)
	}
	defer client.Close()

	return client.Device(iface)
}

func (r *RealExecutor) ListConfigs() ([]string, error) {
	pattern := filepath.Join(r.configDir, "*.conf")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("扫描配置目录失败: %w", err)
	}

	var configs []string
	for _, f := range files {
		base := filepath.Base(f)
		configs = append(configs, strings.TrimSuffix(base, filepath.Ext(base)))
	}
	return configs, nil
}

func (r *RealExecutor) ReadConfigFile(confName string) ([]byte, error) {
	path := resolveConfigPath(r.configDir, confName)
	return os.ReadFile(path)
}

func (r *RealExecutor) WriteConfigFile(confName string, data []byte) error {
	path := resolveConfigPath(r.configDir, confName)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("原子替换配置文件失败: %w", err)
	}
	return nil
}

func (r *RealExecutor) ReloadWireGuard(confName string) error {
	wgQuickPath := "/usr/bin/wg-quick"
	wgPath := "/usr/bin/wg"

	if _, err := os.Stat(wgQuickPath); os.IsNotExist(err) {
		wgQuickPath = "wg-quick"
	}
	if _, err := os.Stat(wgPath); os.IsNotExist(err) {
		wgPath = "wg"
	}

	confPath := resolveConfigPath(r.configDir, confName)
	cmdStrip := exec.Command(wgQuickPath, "strip", confPath)
	configData, err := cmdStrip.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("wg-quick strip 失败: %v, stderr: %s", err, string(exitErr.Stderr))
		}
		return fmt.Errorf("wg-quick strip 失败: %v", err)
	}

	cmdSync := exec.Command(wgPath, "syncconf", confName, "/dev/stdin")
	cmdSync.Stdin = bytes.NewReader(configData)

	if output, err := cmdSync.CombinedOutput(); err != nil {
		return fmt.Errorf("wg syncconf 失败: %v, output: %s", err, string(output))
	}

	logger.Printf("WireGuard (%s) 热重载成功", confName)
	return nil
}

func (r *RealExecutor) Ping(ctx context.Context, ipStr string, count int) (*PingResponse, error) {
	if count <= 0 {
		count = 4
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("无效的 IP 地址: %s", ipStr)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", strconv.Itoa(count), ipStr)
	} else {
		if ip.To4() == nil {
			cmd = exec.CommandContext(ctx, "ping", "-6", "-c", strconv.Itoa(count), "-W", "1", ipStr)
		} else {
			cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "1", ipStr)
		}
	}

	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	res := &PingResponse{
		Address: ipStr,
	}

	if runtime.GOOS == "windows" {
		parseWindowsPing(res, outStr)
	} else {
		parseLinuxPing(res, outStr)
	}

	if res.PacketsReceived > 0 {
		res.IsAlive = true
	}

	return res, nil
}

func (r *RealExecutor) Traceroute(ctx context.Context, ipStr string, maxHops int) (*TracerouteResponse, error) {
	if maxHops <= 0 || maxHops > 30 {
		maxHops = 30
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("无效的 IP 地址: %s", ipStr)
	}

	res := &TracerouteResponse{
		Target: ipStr,
		Hops:   make([]TracerouteHop, 0),
	}

	var outStr string
	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", "1000", ipStr)
		out, _ := cmd.CombinedOutput()
		outStr = string(out)
		parseWindowsTracert(res, outStr)
	} else {
		cmd := exec.CommandContext(ctx, "traceroute", "-n", "-I", "-w", "1", "-m", strconv.Itoa(maxHops), "-q", "3", ipStr)
		out, err := cmd.CombinedOutput()
		outStr = string(out)

		if err != nil && len(out) < 10 {
			cmd2 := exec.CommandContext(ctx, "traceroute", "-n", "-w", "1", "-m", strconv.Itoa(maxHops), "-q", "3", ipStr)
			out2, _ := cmd2.CombinedOutput()
			if len(out2) > len(out) {
				outStr = string(out2)
			}
		}
		res.RawOutput = outStr
		parseLinuxTraceroute(res, outStr)
	}

	return res, nil
}
