package envdetect

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type Decision struct {
	PreferredEngine string // "masscan" | "nmap"
	Reason          string
	Interface       string // default interface if detected
	WaitSeconds     int    // recommended wait
}

// DetectDefaultInterface: пытается определить default dev через `ip route show default`
func DetectDefaultInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ip route error: %w (%s)", err, out.String())
	}
	line := strings.TrimSpace(out.String())
	// пример: default via 172.20.10.1 dev wlp0s20f3 proto dhcp metric 600
	parts := strings.Fields(line)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "dev" {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("cannot parse default interface from: %s", line)
}

func localIPs() map[string]struct{} {
	out := map[string]struct{}{}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ip != nil {
				out[ip.String()] = struct{}{}
			}
		}
	}
	out["127.0.0.1"] = struct{}{}
	out["::1"] = struct{}{}
	return out
}

func isDockerishCIDR(target string) bool {
	// типичные docker ranges: 172.17.0.0/16 ... 172.31/16, 192.168.0.0/16 и т.д. — но docker чаще 172.17/16
	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	// если это /16 в 172.17/16..172.31/16 — скорее docker/bridge
	ip := ipnet.IP.To4()
	if ip == nil {
		return false
	}
	if ip[0] == 172 && ip[1] >= 17 && ip[1] <= 31 {
		return true
	}
	return false
}

func isSingleIP(s string) bool {
	return net.ParseIP(s) != nil
}

func Decide(targets []string) Decision {
	lips := localIPs()

	// rules:
	// - self/localhost -> nmap
	// - docker-like cidr -> nmap (masscan unreliable on docker bridge)
	// - small target set of single IPs in private ranges -> nmap is acceptable but we still prefer masscan unless docker/self
	// - otherwise -> masscan
	for _, t := range targets {
		if t == "localhost" {
			return Decision{PreferredEngine: "nmap", Reason: "localhost target", WaitSeconds: 2}
		}
		if isSingleIP(t) {
			if _, ok := lips[t]; ok {
				return Decision{PreferredEngine: "nmap", Reason: "self-scan target (local IP)", WaitSeconds: 2}
			}
			// docker bridge container IP often 172.17.0.x and reachable only via docker0; masscan may fail
			ip := net.ParseIP(t)
			if ip4 := ip.To4(); ip4 != nil && ip4[0] == 172 && ip4[1] >= 17 && ip4[1] <= 31 {
				return Decision{PreferredEngine: "nmap", Reason: "docker-like target range", WaitSeconds: 2}
			}
		} else if strings.Contains(t, "/") && isDockerishCIDR(t) {
			return Decision{PreferredEngine: "nmap", Reason: "docker-like CIDR range", WaitSeconds: 2}
		}
	}

	return Decision{PreferredEngine: "masscan", Reason: "default", WaitSeconds: 5}
}
