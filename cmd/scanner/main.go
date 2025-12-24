package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/L1nMay/portscanner/internal/banner"
	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/masscan"
	"github.com/L1nMay/portscanner/internal/model"
	"github.com/L1nMay/portscanner/internal/notifier"
	"github.com/L1nMay/portscanner/internal/storage"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	if len(cfg.Targets) == 0 {
		logger.Fatalf("no targets specified in config")
	}

	if cfg.DBPath == "" {
		logger.Fatalf("db_path is not set in config")
	}

	if err := ensureDBDir(cfg.DBPath); err != nil {
		logger.Fatalf("failed to ensure db dir: %v", err)
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

	// 1. Запускаем masscan
	scanResults, err := masscan.Run(cfg)
	if err != nil {
		logger.Errorf("masscan error: %v", err)
	}

	logger.Infof("masscan returned %d open ports", len(scanResults))

	// 2. Обрабатываем результаты: фильтруем новые, собираем баннеры
	var newResults []*model.ScanResult

	for _, r := range scanResults {
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		exists, err := store.Exists(key)
		if err != nil {
			logger.Errorf("storage exists error for %s: %v", key, err)
			continue
		}
		if exists {
			// порт уже видели, пропускаем
			continue
		}

		// Новый порт, пробуем снять баннер
		logger.Infof("new open port found: %s:%d, grabbing banner...", r.IP, r.Port)
		bannerStr, service, err := banner.GrabBanner(r.IP, r.Port, cfg)
		if err != nil {
			logger.Errorf("failed to grab banner for %s:%d: %v", r.IP, r.Port, err)
		}

		res := &model.ScanResult{
			IP:        r.IP,
			Port:      r.Port,
			Proto:     r.Proto,
			Banner:    bannerStr,
			Service:   service,
			FirstSeen: time.Now().UTC(),
		}

		if err := store.PutResult(res); err != nil {
			logger.Errorf("failed to store result for %s:%d: %v", r.IP, r.Port, err)
			continue
		}

		newResults = append(newResults, res)
	}

	// 3. Отправляем уведомления (если есть, о чём уведомлять)
	if notif != nil && len(newResults) > 0 {
		if err := notif.NotifyNewOpenPorts(newResults); err != nil {
			logger.Errorf("failed to send notifications: %v", err)
		}
	} else if len(newResults) == 0 {
		logger.Infof("no new open ports found")
	}
}

// ensureDBDir создаёт директорию для БД, если её ещё нет
func ensureDBDir(dbPath string) error {
	dir := dirOfPath(dbPath)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

func dirOfPath(path string) string {
	idx := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ""
	}
	return path[:idx]
}
