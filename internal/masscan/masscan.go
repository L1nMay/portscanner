package masscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
)

// {"ip":"192.168.0.1","timestamp":"1660000000","ports":[{"port":80,"proto":"tcp","status":"open"}]}
type masscanPort struct {
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
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

// Run — legacy (без ctx)
func Run(cfg *config.Config) ([]Result, error) {
	return RunCtx(context.Background(), cfg)
}

// RunCtx — ctx-aware запуск masscan (для cancel)
func RunCtx(ctx context.Context, cfg *config.Config) ([]Result, error) {
	var results []Result

	args := []string{
		"-p", cfg.Ports,
		"--rate", fmt.Sprintf("%d", cfg.Rate),
		"--wait", fmt.Sprintf("%d", cfg.WaitSeconds),
		"--output-format", "json",
		"--output-filename", "-",
	}

	if cfg.Interface != "" {
		args = append(args, "--interface", cfg.Interface)
	}

	args = append(args, cfg.Targets...)

	logger.Infof("Running masscan: %s %s", cfg.MasscanPath, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, cfg.MasscanPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe error: %w", err)
	}

	// masscan пишет ошибки в stderr — можно слить в stdout (по желанию)
	// cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start masscan: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	// на всякий случай увеличим буфер (иногда строки бывают длиннее)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		// отмена — выходим быстрее
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return results, ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry masscanEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// иногда masscan пишет не-json строки — не валим весь запуск
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
		logger.Errorf("masscan scanner error: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		// если отменили — это норм
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		return results, fmt.Errorf("masscan finished with error: %w", err)
	}

	return results, nil
}
