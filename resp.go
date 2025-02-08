package main

type Response[T any] struct {
	Code    int32   `json:"code"`
	Message *string `json:"message,omitempty"`
	Data    *T      `json:"data,omitempty"`
	Action  *string `json:"action,omitempty"`
}

type RespCompany struct {
	Name             string `json:"name"`
	ZhName           string `json:"zh_name"`
	EnName           string `json:"en_name"`
	Domain           string `json:"domain"`
	EnableSelfSigned bool   `json:"enable_self_signed"`
	SelfSignedCert   string `json:"self_signed_cert"`
	EnablePublicKey  bool   `json:"enable_public_key"`
	PublicKey        string `json:"public_key"`
}

type RespLoginMethod struct {
	LoginEnableLdap bool     `json:"login_enable_ldap"`
	LoginEnable     bool     `json:"login_enable"`
	LoginOrders     []string `json:"login_orders"`
}

type RespTpsLoginMethod struct {
	Alias    string `json:"alias"`
	LoginURL string `json:"login_url"`
	Token    string `json:"token"`
}

type RespCorplinkLoginMethod struct {
	MFA  bool     `json:"mfa"`
	Auth []string `json:"auth"`
}

type RespLogin struct {
	URL string `json:"url"`
}

type RespOtp struct {
	URL  string `json:"url"`
	Code string `json:"code"`
}

type RespVpnInfo struct {
	APIPort      uint16 `json:"api_port"`
	VPNPort      uint16 `json:"vpn_port"`
	IP           string `json:"ip"`
	ProtocolMode int32  `json:"protocol_mode"`
	Name         string `json:"name"`
	EnName       string `json:"en_name"`
	Icon         string `json:"icon"`
	ID           int32  `json:"id"`
	Timeout      int32  `json:"timeout"`
}

type RespWgExtraInfo struct {
	VPNMtu            uint32   `json:"vpn_mtu"`
	VPNDNS            string   `json:"vpn_dns"`
	VPNDNSBackup      string   `json:"vpn_dns_backup"`
	VPNDNSDomainSplit []string `json:"vpn_dns_domain_split,omitempty"`
	VPNRouteFull      []string `json:"vpn_route_full"`
	VPNRouteSplit     []string `json:"vpn_route_split"`
	V6RouteFull       []string `json:"v6_route_full"`
	V6RouteSplit      []string `json:"v6_route_split"`
}

type RespWgInfo struct {
	IP        string          `json:"ip"`
	IPv6      string          `json:"ipv6"`
	IPMask    string          `json:"ip_mask"`
	PublicKey string          `json:"public_key"`
	Setting   RespWgExtraInfo `json:"setting"`
	Mode      uint32          `json:"mode"`
}
