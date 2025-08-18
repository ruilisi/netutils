package device

import (
	"net"
	"sort"
)

// firstMAC gets the MAC address of the most "common" interface.
func firstMAC() string {
	ifces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	weights := map[string]int{
		"eth0":   100,
		"eth1":   90,
		"en0":    80,
		"wlan0":  70,
		"br-lan": 60,
	}

	type candidate struct {
		name string
		mac  string
		w    int
	}
	var list []candidate

	for _, ifc := range ifces {
		if len(ifc.HardwareAddr) == 0 {
			continue
		}
		w := 10
		if v, ok := weights[ifc.Name]; ok {
			w = v
		}
		list = append(list, candidate{name: ifc.Name, mac: ifc.HardwareAddr.String(), w: w})
	}

	if len(list) == 0 {
		return ""
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].w == list[j].w {
			return list[i].name < list[j].name
		}
		return list[i].w > list[j].w
	})

	return list[0].mac
}
