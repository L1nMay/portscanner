package scan

import (
	"fmt"
	"net"
	"strings"

	"github.com/L1nMay/portscanner/internal/envdetect"
)

// ValidateTargets:
// - всегда проверяет корректность формата
// - разрешает одиночный host: IP или hostname, а также /32 (/128)
// - разрешает приватные сети (RFC1918), loopback, link-local всегда
// - публичные адреса/сети разрешает ТОЛЬКО если они попадают в detected local networks
func ValidateTargets(targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	// detect local networks (может быть пусто/ошибка в контейнере)
	nets, err := envdetect.DetectLocalNetworks()
	if err != nil {
		nets = nil
	}

	allowed := make([]*net.IPNet, 0, 16)
	for _, n := range nets {
		_, ipnet, e := net.ParseCIDR(strings.TrimSpace(n.CIDR))
		if e == nil && ipnet != nil {
			allowed = append(allowed, ipnet)
		}
	}

	// helper: принадлежит ли ip хоть одной allowed сети
	inAllowed := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		for _, a := range allowed {
			if a.Contains(ip) {
				return true
			}
		}
		return false
	}

	// helper: private/loopback/link-local
	isSafeIP := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if ip.IsLoopback() {
			return true
		}
		// RFC1918 + fc00::/7
		if ip.IsPrivate() {
			return true
		}
		// 169.254.0.0/16, fe80::/10
		if ip.IsLinkLocalUnicast() {
			return true
		}
		return false
	}

	isSingleHostCIDR := func(ipnet *net.IPNet) bool {
		ones, bits := ipnet.Mask.Size()
		return ones == bits
	}

	// helper: hostname (не IP и не CIDR)
	isHostname := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return false
		}
		// для hostnames допускаем localhost и обычные DNS-имена.
		// запрещаем пробелы/слеши/двоеточия (чтобы не было URL/IPv6:port)
		if strings.ContainsAny(s, " /\\@") {
			return false
		}
		// если выглядит как CIDR — не hostname
		if strings.Contains(s, "/") {
			return false
		}
		// если похоже на IP — не hostname
		if net.ParseIP(s) != nil {
			return false
		}
		// "примерно валидный" DNS label/имя
		// (строго RFC не нужно, главное — не пропускать мусор)
		if len(s) > 253 {
			return false
		}
		return true
	}

	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		if t == "" {
			return fmt.Errorf("invalid target: empty")
		}

		// 0) hostname
		if isHostname(t) {
			// одиночный hostname разрешаем всегда (в т.ч. localhost)
			// (nmap сам резолвит, а мы не хотим ломать fast scan)
			continue
		}

		// 1) одиночный IP
		if ip := net.ParseIP(t); ip != nil {
			// приватные/loopback/linklocal — всегда разрешаем
			if isSafeIP(ip) {
				continue
			}
			// публичные — только если попали в allowed
			if len(allowed) == 0 || !inAllowed(ip) {
				return fmt.Errorf("target %s is outside allowed networks", t)
			}
			continue
		}

		// 2) CIDR
		_, ipnet, e := net.ParseCIDR(t)
		if e != nil || ipnet == nil {
			return fmt.Errorf("invalid target: %s", t)
		}

		baseIP := ipnet.IP
		if baseIP == nil {
			return fmt.Errorf("invalid target: %s", t)
		}

		// /32 (/128) разрешаем как одиночный host:
		// - если safe IP -> ok
		// - если публичный -> только если inAllowed
		if isSingleHostCIDR(ipnet) {
			if isSafeIP(baseIP) {
				continue
			}
			if len(allowed) == 0 || !inAllowed(baseIP) {
				return fmt.Errorf("target %s is outside allowed networks", t)
			}
			continue
		}

		// CIDR НЕ /32:
		// если приватная сеть — разрешаем
		if isSafeIP(baseIP) {
			continue
		}

		// публичная сеть — разрешаем только если её базовый IP попадает в allowed
		if len(allowed) == 0 || !inAllowed(baseIP) {
			return fmt.Errorf("target %s is outside allowed networks", t)
		}
	}

	return nil
}
