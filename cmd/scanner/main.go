package main

import (
	"flag"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/scan"
	"github.com/L1nMay/portscanner/internal/storage"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	// DSN берём из cfg.Database.DSN (туда уже может прилететь ENV DATABASE_DSN через override в LoadConfig)
	pg, err := storage.NewPostgres(cfg.Database.DSN)
	if err != nil {
		logger.Fatalf("failed to connect postgres: %v", err)
	}
	defer pg.Close()

	// migrations
	if err := pg.Migrate("./migrations"); err != nil {
		logger.Fatalf("migrations failed: %v", err)
	}

	// runner
	runner := scan.NewRunner(cfg, nil)
	runner.SetPostgres(pg)

	run, _, err := runner.RunOnce()
	if err != nil {
		logger.Fatalf("scan failed: %v", err)
	}

	logger.Infof(
		"scan finished: engine=%s targets=%d found=%d new=%d",
		run.Engine,
		run.TargetsCount,
		run.Found,
		run.NewFound,
	)
}
