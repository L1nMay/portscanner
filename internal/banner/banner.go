package banner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/L1nMay/portscanner/internal/config"
)

func GrabBanner(ip string, port uint16, cfg *config.Config) (string, string, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	dialer := net.Dialer{
		Timeout: cfg.ConnectTimeout(),
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout())); err != nil {
		return "", "", err
	}

	// Простая логика: для HTTP отправим запрос, для других — просто читаем
	if port == 80 || port == 8080 || port == 8000 || port == 443 {
		// даже для 443 это не идеальный вариант, но для баннера часто хватает
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n"))
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, cfg.BannerMaxBytes)
	n, err := reader.Read(buf)
	if err != nil && !isTimeout(err) {
		return "", "", err
	}

	banner := strings.TrimSpace(string(buf[:n]))
	service := detectService(port, banner)

	return banner, service, nil
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// Очень простая эвристика для определения сервиса по порту/баннеру
func detectService(port uint16, banner string) string {
	lower := strings.ToLower(banner)

	switch port {
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25:
		return "smtp"
	case 80, 8080, 8000:
		if strings.Contains(lower, "http") {
			return "http"
		}
		return "web"
	case 443:
		if strings.Contains(lower, "http") {
			return "https"
		}
		return "tls"
	}

	if strings.Contains(lower, "ssh") {
		return "ssh"
	}
	if strings.Contains(lower, "http") {
		return "http"
	}
	if strings.Contains(lower, "mysql") {
		return "mysql"
	}
	if strings.Contains(lower, "postgres") {
		return "postgresql"
	}

	return "unknown"
}
