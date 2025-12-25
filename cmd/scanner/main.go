package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/notifier"
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

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0755); err != nil {
		logger.Fatalf("failed to create db dir: %v", err)
	}

	store, err := storage.NewStorage(cfg.DBPath)
	if err != nil {
		logger.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	var notif notifier.Notifier
	if cfg.Telegram.Enabled {
		notif = notifier.NewTelegramNotifier(cfg)
	}

	r := scan.NewRunner(cfg, store)

	run, newOnes, err := r.RunOnce()
	if err != nil {
		logger.Fatalf("scan failed: %v", err)
	}

	logger.Infof("scan finished: engine=%s found=%d new=%d", run.Engine, run.Found, run.NewFound)

	if notif != nil && len(newOnes) > 0 {
		if err := notif.NotifyNewOpenPorts(newOnes); err != nil {
			logger.Errorf("notification error: %v", err)
		}
	}
}
