package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/L1nMay/portscanner/internal/config"
	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/model"
)

type TelegramNotifier struct {
	cfg *config.Config
}

func NewTelegramNotifier(cfg *config.Config) *TelegramNotifier {
	return &TelegramNotifier{cfg: cfg}
}

type telegramMessage struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func (t *TelegramNotifier) NotifyNewOpenPorts(results []*model.ScanResult) error {
	if !t.cfg.Telegram.Enabled || len(results) == 0 {
		return nil
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("📡 %s — новые открытые порты:\n\n", t.cfg.ScanName))

	for _, r := range results {
		builder.WriteString(fmt.Sprintf(
			"- %s:%d (%s)\n  Сервис: %s\n  Первый раз замечен: %s\n",
			r.IP,
			r.Port,
			r.Proto,
			r.Service,
			r.FirstSeen.Format(time.RFC3339),
		))
		if r.Banner != "" {
			banner := r.Banner
			if len(banner) > 200 {
				banner = banner[:200] + "..."
			}
			builder.WriteString(fmt.Sprintf("  Баннер: %s\n", banner))
		}
		builder.WriteString("\n")
	}

	msg := telegramMessage{
		ChatID: t.cfg.Telegram.ChatID,
		Text:   builder.String(),
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.cfg.Telegram.BotToken)

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		logger.Errorf("telegram returned non-2xx status: %s", resp.Status)
	}

	return nil
}
