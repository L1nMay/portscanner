package nmap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
)

type Result struct {
	IP    string
	Port  uint16
	Proto string
}

// Run — legacy (без ctx)
func Run(cfg *config.Config) ([]Result, error) {
	return RunCtx(context.Background(), cfg)
}

// RunCtx — ctx-aware запуск nmap (для cancel)
func RunCtx(ctx context.Context, cfg *config.Config) ([]Result, error) {
	var results []Result

	args := []string{
		"-Pn",
		"-sT",
		"-p", cfg.Ports,
	}

	args = append(args, cfg.Targets...)

	logger.Infof("Running nmap: nmap %s", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, "nmap", args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("nmap error: %w", err)
	}

	scanner := bufio.NewScanner(&stdout)
	var currentIP string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Nmap scan report for") {
			parts := strings.Fields(line)
			currentIP = parts[len(parts)-1]
			continue
		}

		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			var port uint16
			fmt.Sscanf(fields[0], "%d/tcp", &port)

			results = append(results, Result{
				IP:    currentIP,
				Port:  port,
				Proto: "tcp",
			})
		}
	}

	return results, nil
}
