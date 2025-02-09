# corplink-go
从rust项目[corplink-rs](https://github.com/PinkD/corplink-rs)翻译而来

1. 去除了cgo依赖
2. 直接使用wireguard-go, 不支持tcp连接。 
3. 可以跨平台编译，支持mac/linux。
4. 目前没做windows的支持


## 编译

```
# 根据需要决定是否启用goproxy
#  

go mod tidy

go mod vendor

go build -o corplink .
```


## 配置
配置文件保存为`config.json`

最小配置
```json
{
  "company_name": "company code",
  "username": "your_name"
}
```

完整配置
```json
{
  "company_name": "company code name",
  "username": "your_name",
  // support sha256sum hashed pass if you don't use ldap, will ask email for code if not provided
  "password": "your_pass",
  // default is feilian, can be feilian/ldap/lark(aka feishu)/OIDC
  // dingtalk/aad/weixin is not supported yet
  "platform": "ldap",
  "code": "totp code",
  // default is DollarOS(not CentOS)
  "device_name": "any string to describe your device",
  "device_id": "md5 of device_name or any string with same format",
  "public_key": "wg public key, can be generated from private key",
  "private_key": "wg private key",
  "server": "server link",
  // enable wg-go log to debug uapi problems
  "debug_wg": true,
  // will use corplink as interface name
  "interface_name": "corplink",
  // will use the specified server to connect, for example 'HK-1'
  // name from server list
  "vpn_server_name": "hk",
  // latency/default
  // latency: choose the server with the lowest latency
  // default: choose the first available server
  "vpn_select_strategy": "latency",
  // use vpn dns for macos
  // NOTE: if process doesn't exit gracefully, your dns may not be restored
  "use_vpn_dns": false
}
```

## 运行
```
./corplink config.json
```
运行时会自动补齐config.json中的部分内容。遇到登录失败删除config.json中的 `"status":"LOGIN"` + 上一行的逗号
