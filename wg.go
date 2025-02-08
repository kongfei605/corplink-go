package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	LogLevelSilent  = 0
	LogLevelError   = 1
	LogLevelVerbose = 2

	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var (
	wgDevice *device.Device
	logger   *device.Logger
	Version  = "unknown" // 确保版本号有定义或通过构建参数注入
)

// UAPI客户端结构体
type UAPIClient struct {
	Name string
}

// 配置WireGuard（对应Rust的config_wg方法）
func (u *UAPIClient) ConfigureWG(conf *WgConf) error {
	var buf bytes.Buffer
	buf.WriteString("set=1\n")

	// 处理密钥
	privateKey, _ := base64.StdEncoding.DecodeString(conf.PrivateKey)
	publicKey, _ := base64.StdEncoding.DecodeString(conf.PeerKey)

	fmt.Fprintf(&buf, "private_key=%x\n", privateKey)
	buf.WriteString("replace_peers=true\n")
	fmt.Fprintf(&buf, "public_key=%x\n", publicKey)
	buf.WriteString("replace_allowed_ips=true\n")
	fmt.Fprintf(&buf, "endpoint=%s\n", conf.PeerAddress)
	buf.WriteString("persistent_keepalive_interval=10\n")

	// 处理路由
	for _, route := range conf.Route {
		if !containsSlash(route) {
			route += "/32"
		}
		fmt.Fprintf(&buf, "allowed_ip=%s\n", route)
	}

	// 地址配置
	fmt.Fprintf(&buf, "address=%s\n", conf.Address)
	if conf.Address6 != "" {
		fmt.Fprintf(&buf, "address=%s\n", conf.Address6)
	}
	fmt.Fprintf(&buf, "mtu=%d\n", conf.MTU)
	buf.WriteString("up=true\n")

	// 处理路由
	for _, route := range conf.Route {
		if containsSlash(route) {
			fmt.Fprintf(&buf, "route=%s\n", route)
		} else {
			prefix := 32
			if containsColon(route) {
				prefix = 128
			}
			fmt.Fprintf(&buf, "route=%s/%d\n", route, prefix)
		}
	}

	buf.WriteString("\n")
	return u.processUAPI(buf.String())
}

// 处理UAPI请求
func (u *UAPIClient) processUAPI(cmd string) error {

	result := UAPI(cmd)
	if !strings.Contains(result, "errno=0") {
		return errors.New("UAPI error: " + result)
	}
	return nil
}

// 连接检查（对应Rust的check_wg_connection）
func (u *UAPIClient) CheckWgConnection(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if u.checkHandshake() {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (u *UAPIClient) checkHandshake() bool {
	cmd := "get=1\n\n"
	result := UAPI(cmd)
	lines := strings.Split(result, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "last_handshake_time_sec") {
			parts := strings.Split(line, "=")
			if len(parts) < 2 {
				continue
			}

			timestamp, _ := strconv.ParseInt(parts[1], 10, 64)
			if timestamp == 0 {
				continue
			}

			lastHandshake := time.Unix(timestamp, 0)
			elapsed := time.Since(lastHandshake)
			if elapsed > 5*time.Minute {
				return true
			}
		}
	}
	return false
}

// 辅助函数
func containsSlash(s string) bool { return strings.Contains(s, "/") }
func containsColon(s string) bool { return strings.Contains(s, ":") }

func UAPI(cmdStr string) string {
	content := cmdStr
	cmds := strings.Split(content, "\n")
	var result string

	switch cmds[0] {
	case "set=1":
		logger.Verbosef("Setting uapi configuration")
		config := strings.TrimPrefix(content, "set=1\n")
		err := wgDevice.IpcSetOperation(strings.NewReader(config))

		var status *device.IPCError
		switch {
		case err == nil:
			result = "errno=0\n\n"
		case errors.As(err, &status):
			result = fmt.Sprintf("errno=%d\n\n", status.ErrorCode())
		default:
			result = fmt.Sprintf("errno=%d\n\n", ipc.IpcErrorUnknown)
		}

	case "get=1":
		logger.Verbosef("Getting uapi configuration")
		config, err := wgDevice.IpcGet()

		var status *device.IPCError
		switch {
		case err == nil:
			result = config + "errno=0\n\n"
		case errors.As(err, &status):
			result = fmt.Sprintf("errno=%d\n\n", status.ErrorCode())
		default:
			result = fmt.Sprintf("errno=%d\n\n", ipc.IpcErrorUnknown)
		}

	default:
		logger.Verbosef("Unknown uapi command")
		result = fmt.Sprintf("errno=%d\n\n", ipc.IpcErrorUnknown)
	}

	return result
}

func StopWgGo() {
	if wgDevice != nil {
		wgDevice.Close()
		logger.Verbosef("Shutting down WireGuard device")
	}
}

func StartWgGo(logLevel int, protocol int, ifaceName string) int {
	logger = device.NewLogger(
		logLevel,
		fmt.Sprintf("wg-corplink(%s) ", ifaceName),
	)

	tunDevice, err := tun.CreateTUN(ifaceName, device.DefaultMTU)
	if err == nil {
		if realName, err := tunDevice.Name(); err == nil {
			ifaceName = realName
		}
	}

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		return ExitSetupFailed
	}

	logger.Verbosef("Starting wg-corplink version %s", Version)

	switch protocol {
	case 0: // UDP协议
		wgDevice = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	case 1: // TCP协议
		// wgDevice = device.NewDevice(tunDevice, conn.NewTCPBind(), logger)
		wgDevice = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	default:
		logger.Errorf("Unsupported protocol: %d", protocol)
		return ExitSetupFailed
	}

	logger.Verbosef("WireGuard device %s initialized", ifaceName)
	return ExitSetupSuccess
}
