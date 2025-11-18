package servers

var CNDNSServersSmall = []string{
	"114.114.114.114:53", // 114 DNS
	"223.5.5.5:53",       // 阿里云 DNS
	"119.29.29.29:53",    // DNSPod DNS
}

var CNDNSServers = []string{
	"114.114.114.114:53", // 114 DNS
	"114.114.115.115:53", // 114 DNS 备用
	"223.5.5.5:53",       // 阿里云 DNS
	"223.6.6.6:53",       // 阿里云 DNS 备用
	"119.29.29.29:53",    // DNSPod DNS
	"119.28.28.28:53",    // DNSPod DNS 备用
	"180.76.76.76:53",    // 百度云 DNS
	"1.2.4.8:53",         // CNNIC SDK DNS
	"210.2.4.8:53",       // CNNIC SDK DNS 备用
}

var SecurityDNSServers = []string{
	"114.114.114.119:53", // 114 DNS 安全版
	"114.114.115.119:53", // 114 DNS 安全版 备用
	"101.226.4.6:53",     // 360 DNS (电信/移动/铁通)
	"123.125.81.6:53",    // 360 DNS (联通)
	"9.9.9.9:53",         // Quad9 安全DNS
}

var InternationalDNSServers = []string{
	"8.8.8.8:53",        // Google DNS
	"8.8.4.4:53",        // Google DNS 备用
	"1.1.1.1:53",        // Cloudflare DNS
	"1.0.0.1:53",        // Cloudflare DNS 备用
	"208.67.222.222:53", // OpenDNS
	"208.67.220.220:53", // OpenDNS 备用
}

var AllDNSServersDeprecated = append(append(CNDNSServers, SecurityDNSServers...), InternationalDNSServers...)
