package masscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
)

// Структуры под JSON-вывод masscan'а.
// Пример строки JSON (может отличаться в зависимости от версии masscan):
// {"ip":"192.168.0.1","timestamp":"1660000000","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]}

type masscanPort struct {
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
	// Остальные поля нам не критичны
}

type masscanEntry struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

type Result struct {
	IP    string
	Port  uint16
	Proto string
}

// Run запускает masscan и возвращает список открытых портов.
func Run(cfg *config.Config) ([]Result, error) {
	var results []Result

	args := []string{
		"-p", cfg.Ports,
		"--rate", fmt.Sprintf("%d", cfg.Rate),
		"--wait", "0",
		"--output-format", "json",
		"--output-filename", "-",
	}

	args = append(args, cfg.Targets...)

	logger.Infof("Running masscan: %s %s", cfg.MasscanPath, strings.Join(args, " "))

	cmd := exec.Command(cfg.MasscanPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe error: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start masscan: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry masscanEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			logger.Errorf("failed to parse masscan json: %v (line: %s)", err, line)
			continue
		}

		for _, p := range entry.Ports {
			results = append(results, Result{
				IP:    entry.IP,
				Port:  p.Port,
				Proto: p.Proto,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Errorf("scanner error: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return results, fmt.Errorf("masscan finished with error: %w", err)
	}

	return results, nil
}
