package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"

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

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		logger.Fatalf("failed to create db dir: %v", err)
	}

	store, err := storage.NewStorage(cfg.DBPath)
	if err != nil {
		logger.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	runner := scan.NewRunner(cfg, store)
	srv := webui.NewServer(cfg, store, runner)

	addr := cfg.WebUI.Listen
	logger.Infof("Web UI listening on http://%s", addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		logger.Fatalf("web ui server error: %v", err)
	}
}
