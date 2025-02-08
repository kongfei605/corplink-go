package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
)

const (
	DefaultDeviceName    = "DollarOS"
	DefaultInterfaceName = "corplink"

	PlatformLDAP     = "ldap"
	PlatformCorplink = "feilian"
	PlatformOIDC     = "OIDC"
	PlatformLark     = "lark"
	PlatformWeixin   = "weixin"
	PlatformDingTalk = "dingtalk"
	PlatformAAD      = "aad"

	StrategyLatency = "latency"
	StrategyDefault = "default"
)

type Config struct {
	CompanyName       string  `json:"company_name"`
	Username          string  `json:"username"`
	Password          *string `json:"password,omitempty"`
	Platform          *string `json:"platform,omitempty"`
	Code              *string `json:"code,omitempty"`
	DeviceName        *string `json:"device_name,omitempty"`
	DeviceID          *string `json:"device_id,omitempty"`
	PublicKey         *string `json:"public_key,omitempty"`
	PrivateKey        *string `json:"private_key,omitempty"`
	Server            *string `json:"server,omitempty"`
	InterfaceName     *string `json:"interface_name,omitempty"`
	DebugWg           *bool   `json:"debug_wg,omitempty"`
	ConfFile          *string `json:"-"`
	State             *State  `json:"state,omitempty"`
	VPNServerName     *string `json:"vpn_server_name,omitempty"`
	VPNSelectStrategy *string `json:"vpn_select_strategy,omitempty"`
	UseVPNDNS         *bool   `json:"use_vpn_dns,omitempty"`
}

func (c Config) String() string {
	bytes, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		panic(fmt.Sprintf("failed to marshal config: %v", err))
	}
	return string(bytes)
}

func ConfigFromFile(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", file, err)
	}

	var conf Config
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %v", file, err)
	}

	conf.ConfFile = &file
	updateConf := false

	if conf.InterfaceName == nil {
		interfaceName := DefaultInterfaceName
		conf.InterfaceName = &interfaceName
		updateConf = true
	}

	if conf.DeviceName == nil {
		deviceName := DefaultDeviceName
		conf.DeviceName = &deviceName
		updateConf = true
	}

	if conf.DeviceID == nil {
		hash := md5.Sum([]byte(*conf.DeviceName))
		deviceID := fmt.Sprintf("%x", hash)
		conf.DeviceID = &deviceID
		updateConf = true
	}

	// Handle key generation/derivation
	if conf.PrivateKey != nil {
		if conf.PublicKey == nil {
			pubKey, err := GenPublicKeyFromPrivate(*conf.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to generate public key: %v", err)
			}
			conf.PublicKey = &pubKey
			updateConf = true
		}
	} else {
		pubKey, privKey := GenWgKeypair()
		conf.PublicKey = &pubKey
		conf.PrivateKey = &privKey
		updateConf = true
	}

	if updateConf {
		if err := conf.Save(); err != nil {
			return nil, err
		}
	}

	return &conf, nil
}

func (c *Config) Save() error {
	if c.ConfFile == nil {
		return fmt.Errorf("config file path not set")
	}

	data := c.String()
	return os.WriteFile(*c.ConfFile, []byte(data), 0644)
}

type WgConf struct {
	// Standard wg conf
	Address     string   `json:"address"`
	Address6    string   `json:"address6"`
	PeerAddress string   `json:"peer_address"`
	MTU         uint32   `json:"mtu"`
	PublicKey   string   `json:"public_key"`
	PrivateKey  string   `json:"private_key"`
	PeerKey     string   `json:"peer_key"`
	Route       []string `json:"route"`

	// Extended confs
	DNS string `json:"dns"`

	// Corplink confs
	Protocol int32 `json:"protocol"`
}
