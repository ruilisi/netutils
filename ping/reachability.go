package ping

import (
	"net"
	"time"
)

func CheckReachability() bool {
	ch := make(chan bool)
	go func() {
		ips, _ := net.LookupIP("www.qq.com")
		if len(ips) > 0 {
			select {
			case ch <- true:
			default:
			}
		}
	}()
	tryPing := func(addr string) {
		if FastPing(addr, time.Second) == nil {
			select {
			case ch <- true:
			default:
			}
		}
	}
	go tryPing("223.5.5.5")
	go tryPing("119.29.29.29")
	go tryPing("114.114.114.114")
	select {
	case <-ch:
		return true
	case <-time.After(time.Second):
		return false
	}
}
