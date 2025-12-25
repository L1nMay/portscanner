package scan

import (
	"strings"

	"github.com/L1nMay/portscanner/internal/logger"
)

func resolvePorts(ports string, engine string) string {
	p := strings.TrimSpace(strings.ToLower(ports))

	if p == "" || p == "auto" {
		if engine == "masscan" {
			logger.Infof("Auto ports resolved for masscan: 1-65535")
			return "1-65535"
		}
		logger.Infof("Auto ports resolved for nmap: 1-1024,8080,8443,3000,5000,8000,8087,9000")
		return "1-1024,8080,8443,3000,5000,8000,8087,9000"
	}

	if p == "top" {
		logger.Infof("Top ports mode enabled")
		return "22,21,25,53,80,110,143,443,3306,5432,6379,27017,8080,8443"
	}

	return ports
}
