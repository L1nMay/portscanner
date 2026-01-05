package main

import (
	"flag"
	"net/http"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/scan"
	"github.com/L1nMay/portscanner/internal/storage"
	"github.com/L1nMay/portscanner/internal/webui"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

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

	// web ui
	server := webui.NewServer(cfg, pg, runner)

	logger.Infof("Web UI listening on http://%s", cfg.WebUI.Listen)
	if err := http.ListenAndServe(cfg.WebUI.Listen, server.Handler()); err != nil {
		logger.Fatalf("web ui error: %v", err)
	}
}
