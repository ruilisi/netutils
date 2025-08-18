//go:build darwin

package device

import (
	"os/exec"
	"strings"
)

func uniqIDRaw() string {
	out, err := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					return parts[3]
				}
			}
		}
	}

	return firstMAC()
}
