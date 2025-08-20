# netutils

## 概述
使用Go语言编写的网络工具集，专注于解决各类网络疑难杂症。提供高效的网络诊断、连接测试、协议分析等功能，帮助开发者和运维人员快速定位和解决网络相关问题。

## 工具介绍

### device
设备有关的工具
#### 生成设备的唯一ID,支持window、macOS、linux darwin操作系统
    device/uniq_id.go -> GetUniqId() 

### dns
dns有关的工具
#### 寻找ip在本地dns对应的域名
    dns/dns.go -> LookupAddrLocalDNS(addr string) ([]string, error) 

### ds(Data Structure)
#### 使用Go 泛型实现的set 结构，包含add,remove has,values 方法，并发不安全
    ds/set.go

### http
http 相关工具
#### http 下载流量计数器，采用装饰器模式封装了ReadCounterConn
    http/http.go/ReadCounterConn
#### 原始Get 请求构造器,默认是80端口
    http/http.go -> BuildRawRequest(url string, headers map[string]string) ([]byte, error)

#### Tcp下载速度测试，统计tcp连接的下载速度
    http/http.go -> DownloadSpeedTCP(conn net.Conn, reqBytes []byte, duration time.Duration) (float64, error)

#### URL解析工具，将形如 `https://example.com:8080/path?key=value#frag` 的字符串解析为url.URL
    http/http.go -> HostPortFromURL(rawURL string) (string, *url.URL, error)

### ip
和 ip地址相关的工具
#### ipv6检测器 支持CIDR、普通形式 的net.IP,net.IPNet,String 判断它是否是一个ipv6
    ip/ip.go -> IsIPV6(ip *net.IP) bool | IsIPNetV6(cidr *net.IPNet) bool | IsIPNetStrV6B(ipNetStr string) bool
                IsIPNetStrV6(ipNetStr string) (bool, error) 

#### 全掩码生成器，支持net.IP 和 string 两种格式的ip地址
    ip/ip.go -> IP2IPNetFullMask(ip net.IP) net.IPNet | IPStrFullMask(ipStr string) (string, error)

#### 默认地址检测器，检查ip地址是否是全0
    ip/ip.go -> IsDefaultIP(ip net.IP) bool | IsDefaultIP(ip net.IP) bool

#### IPv4 字符串转 CIDR 形式字符串，后缀自动添加 "/32"，不支持IPv6
    ip/ip.go -> IP2CIDR(ip string) string

#### 获得IPv4的广播地址
    ip/ip.go ->  GetBroadcastIPV4OfIPNet(ipnet *net.IPNet) string

#### 判断两个Net.IPNEet 是否相等
    ip/ip.go -> EqualIPNet(a, b *net.IPNet) bool

#### 判断某个ip字段是否在net.ipNet里面
    ip/ip.go -> IsIPStrInNet(ipStr string, ipNet *net.IPNet)

#### 获得网络流量的出口设备
    ip/outbound.go ->  GetOutboundInterface() (*net.Interface, error)

#### 获得出口设备的ip
    ip/outbound.go -> GetOutboundIP(iface *net.Interface) (string, error)

#### 获得出口设备的ipNet
    ip/outbound.go -> GetOutboundIPNet(iface *net.Interface) (*net.IPNet, error)

#### 判断是否是私有地址，根据RFC1918 作为标准
    ip/private.go ->  IsPrivateNetwork(ipnet *net.IPNet) bool | IsPrivateIP(ip net.IP) bool

### ping
探测相关工具
#### 向指定的 IP 地址发送ping，并在指定的超时时间内等待回复，如果成功返回回复的值，失败返回nil
    ping/ping.go -> FastPing(addr string, timeout time.Duration) error

#### 通过cmd 向指定的 IP 地址发送ping，并在指定的超时时间内等待回复,成功返回往返时间
    ping/ping.go -> PingCmd

#### 检查设备联网能力，通过dns+多个ping 目标检测设备的联网能力
    ping/reachability.go -> CheckReachability() bool