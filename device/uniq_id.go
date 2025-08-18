package device

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
)

// GetUniqID returns a stable unique device identifier (shortened hash or fallback random).
func GetUniqID() string {
	raw := uniqIDRaw()
	if raw != "" {
		return raw
	}

	path := deviceIDPath()
	if id, err := os.ReadFile(path); err == nil {
		return string(id)
	}

	b := make([]byte, 8) // 64-bit random → 16 hex chars
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)

	_ = os.WriteFile(path, []byte(id), 0644)
	return id
}

// deviceIDPath decides where to store fallback ID file.
func deviceIDPath() string {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc"); err == nil {
			return "/etc/device_id"
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "device_id")
	}
	return filepath.Join(home, ".device_id")
}
