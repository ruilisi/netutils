//go:build linux

package device

import (
	"os"
	"strings"
)

// uniqIDRaw tries to get a stable identifier for Linux/OpenWrt.
func uniqIDRaw() string {
	// 1. Try systemd machine-id
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}

	// 2. Try older D-Bus machine-id
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}

	// 3. Try MAC
	return firstMAC()
}
