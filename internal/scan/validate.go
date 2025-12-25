package scan

import (
	"fmt"
	"net"

	"github.com/L1nMay/portscanner/internal/envdetect"
)

// ValidateTargets запрещает сканирование вне локальных сетей
func ValidateTargets(targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	nets, err := envdetect.DetectLocalNetworks()
	if err != nil {
		return err
	}

	var allowed []*net.IPNet
	for _, n := range nets {
		_, ipnet, err := net.ParseCIDR(n.CIDR)
		if err == nil && ipnet != nil {
			allowed = append(allowed, ipnet)
		}
	}

	for _, t := range targets {
		ip := net.ParseIP(t)
		if ip == nil {
			// пробуем CIDR
			_, ipnet, err := net.ParseCIDR(t)
			if err != nil {
				return fmt.Errorf("invalid target: %s", t)
			}
			// проверяем, что CIDR внутри разрешённых
			ok := false
			for _, a := range allowed {
				if a.Contains(ipnet.IP) {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("target %s is outside allowed networks", t)
			}
			continue
		}

		ok := false
		for _, a := range allowed {
			if a.Contains(ip) {
				ok = true
				break
			}
		}

		if !ok {
			return fmt.Errorf("target %s is outside allowed networks", t)
		}
	}

	return nil
}
