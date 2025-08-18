//go:build windows

package device

import (
	"os/exec"
	"strings"
)

func uniqIDRaw() string {
	out, err := exec.Command("wmic", "bios", "get", "serialnumber").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 1 {
			id := strings.TrimSpace(lines[1])
			if id != "" && id != "To Be Filled By O.E.M." {
				return id
			}
		}
	}

	return firstMAC()
}
