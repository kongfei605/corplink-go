package main

import (
	"bytes"
	"fmt"
	"html/template"
)

const URLGetCompany = "https://corplink.volcengine.cn/api/match"

const (
	URLGetLoginMethod         = "{{.URL}}/api/login/setting?os={{.OS}}&os_version={{.Version}}"
	URLGetTpsLoginMethod      = "{{.URL}}/api/tpslogin/link?os={{.OS}}&os_version={{.Version}}"
	URLGetTpsTokenCheck       = "{{.URL}}/api/tpslogin/token/check?os={{.OS}}&os_version={{.Version}}"
	URLGetCorplinkLoginMethod = "{{.URL}}/api/lookup?os={{.OS}}&os_version={{.Version}}"
	URLRequestCode            = "{{.URL}}/api/login/code/send?os={{.OS}}&os_version={{.Version}}"
	URLVerifyCode             = "{{.URL}}/api/login/code/verify?os={{.OS}}&os_version={{.Version}}"
	URLLoginPassword          = "{{.URL}}/api/login?os={{.OS}}&os_version={{.Version}}"
	URLListVPN                = "{{.URL}}/api/vpn/list?os={{.OS}}&os_version={{.Version}}"
	URLPingVPNHost            = "{{.URL}}/vpn/ping?os={{.OS}}&os_version={{.Version}}"
	URLFetchPeerInfo          = "{{.URL}}/vpn/conn?os={{.OS}}&os_version={{.Version}}"
	URLOperateVPN             = "{{.URL}}/vpn/report?os={{.OS}}&os_version={{.Version}}"
	URLOTP                    = "{{.URL}}/api/v2/p/otp?os={{.OS}}&os_version={{.Version}}"
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
	UserParam    UserUrlParam
	VpnParam     VpnUrlParam
	ApiTemplates map[ApiName]*template.Template
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
		tmpl, err := template.New(fmt.Sprint(name)).Parse(tmplStr)
		if err != nil {
			panic(err)
		}
		apiTemplates[name] = tmpl
	}

	return &ApiURL{
		UserParam: UserUrlParam{
			URL:     *conf.Server,
			OS:      os,
			Version: version,
		},
		VpnParam: VpnUrlParam{
			URL:     "",
			OS:      os,
			Version: version,
		},
		ApiTemplates: apiTemplates,
	}
}

func (a *ApiURL) GetApiURL(name ApiName) string {
	var buf bytes.Buffer
	var err error

	switch name {
	case PingVPN, ConnectVPN, KeepAliveVPN, DisconnectVPN:
		err = a.ApiTemplates[name].Execute(&buf, a.VpnParam)
	default:
		err = a.ApiTemplates[name].Execute(&buf, a.UserParam)
	}
	if err != nil {
		panic(err)
	}

	return buf.String()
}
