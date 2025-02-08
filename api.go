package main

import (
	"bytes"
	"html/template"
)

const URLGetCompany = "https://corplink.volcengine.cn/api/match"

const (
	URLGetLoginMethod         = "{{.url}}/api/login/setting?os={{.os}}&os_version={{.version}}"
	URLGetTpsLoginMethod      = "{{.url}}/api/tpslogin/link?os={{.os}}&os_version={{.version}}"
	URLGetTpsTokenCheck       = "{{.url}}/api/tpslogin/token/check?os={{.os}}&os_version={{.version}}"
	URLGetCorplinkLoginMethod = "{{.url}}/api/lookup?os={{.os}}&os_version={{.version}}"
	URLRequestCode            = "{{.url}}/api/login/code/send?os={{.os}}&os_version={{.version}}"
	URLVerifyCode             = "{{.url}}/api/login/code/verify?os={{.os}}&os_version={{.version}}"
	URLLoginPassword          = "{{.url}}/api/login?os={{.os}}&os_version={{.version}}"
	URLListVPN                = "{{.url}}/api/vpn/list?os={{.os}}&os_version={{.version}}"
	URLPingVPNHost            = "{{.url}}/vpn/ping?os={{.os}}&os_version={{.version}}"
	URLFetchPeerInfo          = "{{.url}}/vpn/conn?os={{.os}}&os_version={{.version}}"
	URLOperateVPN             = "{{.url}}/vpn/report?os={{.os}}&os_version={{.version}}"
	URLOTP                    = "{{.url}}/api/v2/p/otp?os={{.os}}&os_version={{.version}}"
)

type ApiName int

const (
	LoginMethod ApiName = iota
	TpsLoginMethod
	TpsTokenCheck
	CorplinkLoginMethod
	RequestEmailCode
	LoginPassword
	LoginEmail
	ListVPN
	PingVPN
	ConnectVPN
	KeepAliveVPN
	DisconnectVPN
	OTP
)

type UserUrlParam struct {
	URL     string `json:"url"`
	OS      string `json:"os"`
	Version string `json:"version"`
}

type VpnUrlParam struct {
	URL     string `json:"url"`
	OS      string `json:"os"`
	Version string `json:"version"`
}

type ApiURL struct {
	userParam    UserUrlParam
	vpnParam     VpnUrlParam
	apiTemplates map[ApiName]*template.Template
}

func NewApiURL(conf *Config) *ApiURL {
	os := "Android"
	version := "2"

	apiTemplates := make(map[ApiName]*template.Template)

	// 初始化所有模板
	templates := map[ApiName]string{
		LoginMethod:         URLGetLoginMethod,
		TpsLoginMethod:      URLGetTpsLoginMethod,
		TpsTokenCheck:       URLGetTpsTokenCheck,
		CorplinkLoginMethod: URLGetCorplinkLoginMethod,
		RequestEmailCode:    URLRequestCode,
		LoginEmail:          URLVerifyCode,
		LoginPassword:       URLLoginPassword,
		ListVPN:             URLListVPN,
		PingVPN:             URLPingVPNHost,
		ConnectVPN:          URLFetchPeerInfo,
		KeepAliveVPN:        URLOperateVPN,
		DisconnectVPN:       URLOperateVPN,
		OTP:                 URLOTP,
	}

	for name, tmplStr := range templates {
		tmpl, err := template.New(string(name)).Parse(tmplStr)
		if err != nil {
			panic(err)
		}
		apiTemplates[name] = tmpl
	}

	return &ApiURL{
		userParam: UserUrlParam{
			URL:     *conf.Server,
			OS:      os,
			Version: version,
		},
		vpnParam: VpnUrlParam{
			URL:     "",
			OS:      os,
			Version: version,
		},
		apiTemplates: apiTemplates,
	}
}

func (a *ApiURL) GetApiURL(name ApiName) string {
	var buf bytes.Buffer
	var err error

	switch name {
	case PingVPN, ConnectVPN, KeepAliveVPN, DisconnectVPN:
		err = a.apiTemplates[name].Execute(&buf, a.vpnParam)
	default:
		err = a.apiTemplates[name].Execute(&buf, a.userParam)
	}

	if err != nil {
		panic(err)
	}

	return buf.String()
}
