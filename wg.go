package main

/*
#include <stdlib.h>
#include "libwg.h"  // 假设已通过cgo生成对应头文件

extern enum LogLevel {
    LogLevelError,
    LogLevelVerbose
};
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// 对应Rust的start_wg_go函数
func StartWgGo(name string, protocol int, withLog bool) bool {
	logLevel := C.LogLevelError
	if withLog {
		logLevel = C.LogLevelVerbose
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	ret := C.startWg(logLevel, C.int(protocol), cName)
	return ret == 0
}

// 对应Rust的stop_wg_go函数
func StopWgGo() {
	C.stopWg()
}

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
	cCmd := C.CString(cmd)
	defer C.free(unsafe.Pointer(cCmd))

	result := C.uapi(cCmd)
	defer C.free(unsafe.Pointer(result))

	resp := C.GoString(result)
	if !strings.Contains(resp, "errno=0") {
		return errors.New("UAPI error: " + resp)
	}
	return nil
}

// 连接检查（对应Rust的check_wg_connection）
func (u *UAPIClient) MonitorConnection(ctx context.Context) {
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
	cCmd := C.CString("get=1\n\n")
	defer C.free(unsafe.Pointer(cCmd))

	result := C.uapi(cCmd)
	defer C.free(unsafe.Pointer(result))

	resp := C.GoString(result)
	lines := strings.Split(resp, "\n")

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
