package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	cookieFileSuffix = "cookies.json"
	userAgent        = "CorpLink/201000 (GooglePixel; Android 10; en)"
)

type Error struct {
	msg string
}

func (e Error) Error() string {
	return e.msg
}

type Client struct {
	conf           *Config
	cookieJar      *cookiejar.Jar
	httpClient     *http.Client
	apiURL         *ApiURL
	dateOffsetSec  int32
	cookieFilePath string
	mu             sync.Mutex
}

func GetCompanyURL(code string) (*RespCompany, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	data := map[string]string{"code": code}
	jsonData, _ := json.Marshal(data)

	resp, err := client.Post(URLGetCompany, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result Response[RespCompany]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Code == 0 {
		return result.Data, nil
	}
	return nil, Error{msg: *result.Message}
}

func NewClient(conf *Config) (*Client, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	confDir := filepath.Dir(*conf.ConfFile)
	if confDir == "" {
		confDir = "."
	}
	cookieFile := filepath.Join(confDir, fmt.Sprintf("%s_%s", *conf.InterfaceName, cookieFileSuffix))

	// Load cookies from file if exists
	if cookieData, err := os.ReadFile(cookieFile); err == nil {
		var cookies []*http.Cookie
		if err := json.Unmarshal(cookieData, &cookies); err == nil {
			if server := conf.Server; server != nil {
				serverURL, _ := url.Parse(*server)
				cookieJar.SetCookies(serverURL, cookies)
			}
		}
	}

	// Add device cookies
	if server := conf.Server; server != nil {
		serverURL, _ := url.Parse(*server)
		if deviceID := conf.DeviceID; deviceID != nil {
			cookieJar.SetCookies(serverURL, []*http.Cookie{{
				Name:  "device_id",
				Value: *deviceID,
			}})
		}
		if deviceName := conf.DeviceName; deviceName != nil {
			cookieJar.SetCookies(serverURL, []*http.Cookie{{
				Name:  "device_name",
				Value: *deviceName,
			}})
		}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Jar:     cookieJar,
		Timeout: 10 * time.Second,
	}

	return &Client{
		conf:           conf,
		cookieJar:      cookieJar,
		httpClient:     httpClient,
		apiURL:         NewApiURL(conf),
		cookieFilePath: cookieFile,
	}, nil
}

func (c *Client) changeState(state State) error {
	c.conf.State = &state
	return c.conf.Save()
}

func (c *Client) saveCookies() error {
	if c.conf.Server == nil {
		return nil
	}
	serverURL, _ := url.Parse(*c.conf.Server)
	cookies := c.cookieJar.Cookies(serverURL)
	cookieData, err := json.Marshal(cookies)
	if err != nil {
		return err
	}
	return os.WriteFile(c.cookieFilePath, cookieData, 0644)
}

func (c *Client) request(api ApiName, body interface{}) (*http.Response, error) {
	apiURL := c.apiURL.GetApiURL(api)

	var req *http.Request
	var err error

	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	} else {
		req, err = http.NewRequest("GET", apiURL, nil)
	}
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, Error{msg: fmt.Sprintf("logout because of bad resp code: %d", resp.StatusCode)}
	}

	c.parseTimeOffsetFromDateHeader(resp)

	// Save cookies if Set-Cookie header is present
	if len(resp.Header["Set-Cookie"]) > 0 {
		c.saveCookies()
	}

	return resp, nil
}

// Login related methods
func (c *Client) NeedLogin() bool {
	return c.conf.State == nil || *c.conf.State == StateInit
}

func (c *Client) Login() error {
	loginMethod, err := c.getLoginMethod()
	if err != nil {
		return err
	}

	tpsLoginMethods, err := c.getTpsLoginMethod()
	if err != nil {
		return err
	}

	tpsLogin := make(map[string]RespTpsLoginMethod)
	for _, resp := range tpsLoginMethods {
		tpsLogin[resp.Alias] = resp
	}

	for _, method := range loginMethod.LoginOrders {
		otpURI, err := c.getOtpURIByOtp(&tpsLogin, method)
		if err != nil {
			log.Printf("Failed to login with method %s: %v", method, err)
			continue
		}

		if otpURI == "" {
			log.Printf("Failed to login with method %s", method)
			continue
		}

		if err := c.changeState(StateLogin); err != nil {
			return err
		}

		parsedURL, err := url.Parse(otpURI)
		if err != nil {
			return err
		}

		query := parsedURL.Query()
		if secret := query.Get("secret"); secret != "" {
			log.Printf("Got 2fa token: %s", secret)
			c.conf.Code = &secret
			if err := c.conf.Save(); err != nil {
				return err
			}
			return nil
		}

		log.Println("Failed to get otp code")
		return nil
	}

	return Error{msg: "no available login method, please provide a valid platform"}
}

func (c *Client) corplinkLogin() (string, error) {
	resp, err := c.getCorplinkLoginMethod()
	if err != nil {
		return "", err
	}

	for _, method := range resp.Auth {
		switch method {
		case "password":
			if c.conf.Password != nil && *c.conf.Password != "" {
				log.Println("Try to login with password")
				return c.loginWithPassword(PlatformCorplink)
			}
			log.Println("No password provided, trying other methods")
		case "email":
			log.Println("Try to login with code from email")
			return c.loginWithEmail()
		default:
			log.Println("Unsupported method %s, trying other methods", method)
		}
	}
	return "", Error{msg: "failed to login with corplink"}
}

func (c *Client) loginWithPassword(platform string) (string, error) {
	password := *c.conf.Password
	body := map[string]interface{}{
		"user_name": c.conf.Username,
	}

	switch platform {
	case PlatformLDAP:
		body["platform"] = PlatformLDAP
	case PlatformCorplink:
		if len(password) != 64 {
			hash := sha256.Sum256([]byte(password))
			password = fmt.Sprintf("%x", hash)
		}
	default:
		return "", Error{msg: fmt.Sprintf("invalid platform %s", platform)}
	}

	body["password"] = password

	var resp Response[RespLogin]
	if err := c.requestJSON(LoginPassword, body, &resp); err != nil {
		return "", err
	}

	if resp.Code == 0 {
		return resp.Data.URL, nil
	}
	return "", Error{msg: *resp.Message}
}

func (c *Client) loginWithEmail() (string, error) {
	log.Println("Try to request code for email")
	if err := c.requestEmailCode(); err != nil {
		return "", err
	}

	log.Println("Input your code from email:")
	code, err := ReadLine()
	if err != nil {
		return "", err
	}
	code = strings.TrimSpace(code)

	body := map[string]interface{}{
		"forget_password": false,
		"code_type":       "email",
		"code":            code,
	}

	var resp Response[RespLogin]
	if err := c.requestJSON(LoginEmail, body, &resp); err != nil {
		return "", err
	}

	if resp.Code == 0 {
		return resp.Data.URL, nil
	}
	return "", Error{msg: fmt.Sprintf("failed to login with email code %s: %s", code, *resp.Message)}
}

// VPN related methods
func (c *Client) ConnectVPN() (*WgConf, error) {
	vpnInfoList, err := c.listVPN()
	if err != nil {
		return nil, err
	}

	log.Printf("Found %d VPN(s)", len(vpnInfoList))

	// Filter VPNs based on configuration
	var filteredVPNs []RespVpnInfo
	for _, vpn := range vpnInfoList {
		if c.conf.VPNServerName != nil && vpn.EnName != *c.conf.VPNServerName {
			log.Printf("Skip %s, expect %s", vpn.EnName, *c.conf.VPNServerName)
			continue
		}

		mode := "unknown protocol"
		switch vpn.ProtocolMode {
		case 1:
			mode = "tcp"
		case 2:
			mode = "udp"
		}

		if mode != "tcp" && mode != "udp" {
			log.Printf("Server name %s does not support %s wg for now", vpn.EnName, mode)
			continue
		}

		filteredVPNs = append(filteredVPNs, vpn)
	}

	// Select VPN based on strategy
	var selectedVPN *RespVpnInfo
	strategy := StrategyDefault
	if c.conf.VPNSelectStrategy != nil {
		strategy = *c.conf.VPNSelectStrategy
	}

	switch strategy {
	case StrategyLatency:
		selectedVPN = c.getFirstVPNByLatency(filteredVPNs)
	case StrategyDefault:
		selectedVPN = c.getFirstAvailableVPN(filteredVPNs)
	default:
		return nil, Error{msg: "unsupported strategy"}
	}

	if selectedVPN == nil {
		return nil, Error{msg: "no vpn available"}
	}

	vpnAddr := fmt.Sprintf("%s:%d", selectedVPN.IP, selectedVPN.VPNPort)
	log.Printf("Try connect to %s, address %s", selectedVPN.EnName, vpnAddr)

	// Get WG configuration
	wgInfo, err := c.fetchPeerInfo(*c.conf.PublicKey)
	if err != nil {
		return nil, err
	}

	// Create WG configuration
	wgConf := &WgConf{
		Address:     fmt.Sprintf("%s/%d", wgInfo.IP, wgInfo.IPMask),
		Address6:    "",
		PeerAddress: vpnAddr,
		MTU:         wgInfo.Setting.VPNMtu,
		PublicKey:   *c.conf.PublicKey,
		PrivateKey:  *c.conf.PrivateKey,
		PeerKey:     wgInfo.PublicKey,
		DNS:         wgInfo.Setting.VPNDNS,
		Protocol:    selectedVPN.ProtocolMode,
	}

	if wgInfo.IPv6 != "" {
		wgConf.Address6 = fmt.Sprintf("%s/128", wgInfo.IPv6)
	}

	// Combine routes
	wgConf.Route = append(wgInfo.Setting.VPNRouteSplit, wgInfo.Setting.V6RouteSplit...)

	return wgConf, nil
}

func (c *Client) KeepAliveVPN(conf *WgConf, interval uint64) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		log.Printf("Keep alive")
		if err := c.reportVPNStatus(conf); err != nil {
			log.Printf("Keep alive error: %v", err)
			return
		}
		<-ticker.C
	}
}

func (c *Client) DisconnectVPN(wgConf *WgConf) error {
	body := map[string]interface{}{
		"ip":         wgConf.Address,
		"public_key": wgConf.PublicKey,
		"mode":       "Split",
		"type":       "101",
	}

	var resp Response[map[string]interface{}]
	if err := c.requestJSON(DisconnectVPN, body, &resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return Error{msg: fmt.Sprintf("failed to disconnect vpn: %s", *resp.Message)}
	}
	return nil
}

// Helper methods
func (c *Client) parseTimeOffsetFromDateHeader(resp *http.Response) {
	if dateStr := resp.Header.Get("Date"); dateStr != "" {
		if serverTime, err := time.Parse(time.RFC1123, dateStr); err == nil {
			now := time.Now()
			offset := serverTime.Sub(now)
			c.dateOffsetSec = int32(offset.Seconds())
		}
	}
}

func (c *Client) requestJSON(api ApiName, body interface{}, result interface{}) error {
	resp, err := c.request(api, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(result)
}

// Login related helper methods
func (c *Client) getLoginMethod() (*RespLoginMethod, error) {
	var resp Response[RespLoginMethod]
	if err := c.requestJSON(LoginMethod, nil, &resp); err != nil {
		return nil, err
	}

	if resp.Code != 0 || resp.Data == nil {
		return nil, Error{msg: fmt.Sprintf("failed to get login method: %s", *resp.Message)}
	}
	return resp.Data, nil
}

func (c *Client) getTpsLoginMethod() ([]RespTpsLoginMethod, error) {
	var resp Response[[]RespTpsLoginMethod]
	if err := c.requestJSON(TpsLoginMethod, nil, &resp); err != nil {
		return nil, err
	}

	if resp.Code != 0 {
		return nil, Error{msg: fmt.Sprintf("failed to get tps login method: %s", *resp.Message)}
	}
	return *resp.Data, nil
}

func (c *Client) getCorplinkLoginMethod() (*RespCorplinkLoginMethod, error) {
	body := map[string]interface{}{
		"forget_password": false,
		"user_name":       c.conf.Username,
	}

	var resp Response[RespCorplinkLoginMethod]
	if err := c.requestJSON(CorplinkLoginMethod, body, &resp); err != nil {
		return nil, err
	}

	if resp.Code != 0 || resp.Data == nil {
		return nil, Error{msg: fmt.Sprintf("failed to get corplink login method: %s", *resp.Message)}
	}
	return resp.Data, nil
}

func (c *Client) requestEmailCode() error {
	body := map[string]interface{}{
		"forget_password": false,
		"code_type":       "email",
		"user_name":       c.conf.Username,
	}

	var resp Response[map[string]interface{}]
	if err := c.requestJSON(RequestEmailCode, body, &resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return Error{msg: fmt.Sprintf("failed to request email code: %s", *resp.Message)}
	}
	return nil
}

// VPN related helper methods
func (c *Client) listVPN() ([]RespVpnInfo, error) {
	var resp Response[[]RespVpnInfo]
	if err := c.requestJSON(ListVPN, nil, &resp); err != nil {
		return nil, err
	}

	switch resp.Code {
	case 0:
		return *resp.Data, nil
	case 101:
		return nil, c.handleLogoutErr(*resp.Message)
	default:
		return nil, Error{msg: fmt.Sprintf("failed to list vpn with error %d: %s", resp.Code, *resp.Message)}
	}
}

func (c *Client) getFirstVPNByLatency(vpnList []RespVpnInfo) *RespVpnInfo {
	var fastestVPN *RespVpnInfo
	minLatency := int64(^uint64(0) >> 1) // maxInt64

	for _, vpn := range vpnList {
		latency := c.pingVPN(vpn.IP, vpn.APIPort)

		status := " timeout"
		if latency != -1 {
			status = fmt.Sprintf(", latency %dms", latency)
		}
		log.Printf("Server name %s%s", vpn.EnName, status)

		if latency != -1 && latency < minLatency {
			vpnCopy := vpn
			fastestVPN = &vpnCopy
			minLatency = latency
		}
	}

	return fastestVPN
}

func (c *Client) getFirstAvailableVPN(vpnList []RespVpnInfo) *RespVpnInfo {
	for _, vpn := range vpnList {
		if latency := c.pingVPN(vpn.IP, vpn.APIPort); latency != -1 {
			return &vpn
		}
	}
	return nil
}

func (c *Client) pingVPN(ip string, apiPort uint16) int64 {
	c.mu.Lock()
	// Save original URL
	originalURL := c.apiURL.vpnParam.URL

	// Update URL for VPN
	serverURL, err := url.Parse(originalURL)
	if err != nil {
		c.mu.Unlock()
		return -1
	}

	serverURL.Host = fmt.Sprintf("%s:%d", ip, apiPort)
	c.apiURL.vpnParam.URL = serverURL.String()
	c.mu.Unlock()

	// Restore original URL when done
	defer func() {
		c.mu.Lock()
		c.apiURL.vpnParam.URL = originalURL
		c.mu.Unlock()
	}()

	startTime := time.Now()
	var resp Response[string]
	if err := c.requestJSON(PingVPN, nil, &resp); err != nil {
		log.Printf("Failed to ping %s:%d: %v", ip, apiPort, err)
		return -1
	}

	latency := time.Since(startTime).Milliseconds()

	if resp.Code != 0 {
		log.Printf("Failed to ping vpn with error %d: %s", resp.Code, *resp.Message)
		return -1
	}

	return latency
}

func (c *Client) fetchPeerInfo(publicKey string) (*RespWgInfo, error) {
	var otp string
	if c.conf.Code != nil && *c.conf.Code != "" {
		decoded, err := B32Decode(*c.conf.Code)
		if err != nil {
			return nil, err
		}

		offset := c.dateOffsetSec / timeStep
		totpSlot := totpOffset(decoded, offset)
		otp = fmt.Sprintf("%06d", totpSlot.Code)
		log.Printf("2fa code generated: %s, %d seconds left", otp, totpSlot.SecsLeft)
	} else {
		log.Printf("Input your 2fa code:")
		var err error
		otp, err = ReadLine()
		if err != nil {
			return nil, err
		}
		otp = strings.TrimSpace(otp)
	}

	body := map[string]interface{}{
		"public_key": publicKey,
		"otp":        otp,
	}

	var resp Response[RespWgInfo]
	if err := c.requestJSON(ConnectVPN, body, &resp); err != nil {
		return nil, err
	}

	switch resp.Code {
	case 0:
		return resp.Data, nil
	case 101:
		return nil, c.handleLogoutErr(*resp.Message)
	default:
		return nil, Error{msg: fmt.Sprintf("failed to fetch peer info with error %d: %s",
			resp.Code, *resp.Message)}
	}
}

func (c *Client) handleLogoutErr(msg string) error {
	if err := c.changeState(StateInit); err != nil {
		return err
	}
	return Error{msg: fmt.Sprintf("operation failed because of logout: %s", msg)}
}

func (c *Client) reportVPNStatus(conf *WgConf) error {
	body := map[string]interface{}{
		"ip":         conf.Address,
		"public_key": conf.PublicKey,
		"mode":       "Split",
		"type":       "100",
	}

	var resp Response[map[string]interface{}]
	if err := c.requestJSON(KeepAliveVPN, body, &resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return Error{msg: fmt.Sprintf("failed to report connection with error %d: %s",
			resp.Code, *resp.Message)}
	}
	return nil
}

// OTP related helper methods
func (c *Client) checkTpsToken(token string) (string, error) {
	body := map[string]interface{}{
		"token": token,
	}

	var resp Response[RespLogin]
	if err := c.requestJSON(TpsTokenCheck, body, &resp); err != nil {
		return "", err
	}

	if resp.Code != 0 {
		return "", Error{msg: *resp.Message}
	}
	return resp.Data.URL, nil
}

func (c *Client) getOtpURIFromTps(method, urlStr, token string) (string, error) {
	log.Printf("Old token is: %s", token)
	log.Printf("Please scan the QR code or visit the following link to auth corplink:\n%s", urlStr)

	qr, err := NewTerminalQrCode([]byte(urlStr))
	if err != nil {
		return "", err
	}
	qr.Print()

	switch method {
	case PlatformLark, PlatformOIDC:
		log.Println("Press enter if you finish auth")
		if _, err := ReadLine(); err != nil {
			return "", err
		}
		return c.checkTpsToken(token)
	default:
		return "", Error{msg: "unsupported platform, please contact the developer"}
	}
}

func (c *Client) getOtpURIByOtp(tpsLogin *map[string]RespTpsLoginMethod, method string) (string, error) {
	url, err := c.getOtpURI(tpsLogin, method)
	if err != nil {
		return "", err
	}

	if url == "" {
		return c.requestOtpCode()
	}
	return url, nil
}

func (c *Client) requestOtpCode() (string, error) {
	var resp Response[RespOtp]
	if err := c.requestJSON(OTP, map[string]interface{}{}, &resp); err != nil {
		return "", err
	}

	if resp.Code != 0 {
		return "", Error{msg: *resp.Message}
	}
	return resp.Data.URL, nil
}
func (c *Client) getOtpURI(tpsLogin *map[string]RespTpsLoginMethod, method string) (string, error) {
	// 首先检查第三方登录方式
	if login, exists := (*tpsLogin)[method]; exists && c.isPlatformOrDefault(method) {
		log.Printf("Try to login with third party platform %s", method)
		return c.getOtpURIFromTps(method, login.LoginURL, login.Token)
	}

	// 检查其他登录方式
	switch method {
	case PlatformCorplink:
		if c.isPlatformOrDefault(PlatformCorplink) {
			log.Printf("Try to login with platform %s", PlatformCorplink)
			return c.corplinkLogin()
		}
	case PlatformLDAP:
		if c.isPlatformOrDefault(PlatformLDAP) {
			log.Printf("Try to login with platform %s", PlatformLDAP)
			return c.ldapLogin()
		}
	}

	return "", nil
}

// 辅助方法，检查平台是否匹配或是默认平台
func (c *Client) isPlatformOrDefault(platform string) bool {
	if c.conf.Platform == nil {
		return true
	}
	return *c.conf.Platform == "" || *c.conf.Platform == platform
}

// LDAP登录方法
func (c *Client) ldapLogin() (string, error) {
	// 首先获取登录方法（虽然我们知道要用LDAP，但API要求这么做）
	resp, err := c.getCorplinkLoginMethod()
	if err != nil {
		return "", err
	}

	for _, method := range resp.Auth {
		if method != "password" {
			continue
		}

		if c.conf.Password != nil && *c.conf.Password != "" {
			return c.loginWithPassword(PlatformLDAP)
		}
		return "", Error{msg: "no password provided"}
	}

	return "", Error{msg: "failed to login with ldap"}
}
