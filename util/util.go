package util

import (
	"fmt"
	"strconv"
	"strings"
)

// DumpHex prints the bytes in a hex + ASCII format
func DumpHex(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		end := min(i+bytesPerLine, len(data))
		// Hex part
		for j := i; j < end; j++ {
			fmt.Printf("%02X ", data[j])
		}

		// Fill space if line < 16 bytes
		for j := end; j < i+bytesPerLine; j++ {
			fmt.Printf("   ")
		}

		// ASCII part
		fmt.Printf("  ")
		for j := i; j < end; j++ {
			c := data[j]
			if c >= 32 && c <= 126 {
				fmt.Printf("%c", c)
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Println()
	}
}

// HexToBytes converts a space-separated hex string to a byte slice
func HexToBytes(hexStr string) ([]byte, error) {
	fields := strings.Fields(hexStr)
	b := make([]byte, len(fields))
	for i, f := range fields {
		val, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q: %v", f, err)
		}
		b[i] = byte(val)
	}
	return b, nil
}
