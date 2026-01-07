package telegram

import (
	"context"
	"fmt"
	"time"

	"github.com/L1nMay/portscanner/internal/logger"
	"github.com/L1nMay/portscanner/internal/storage"
)

type Sender interface {
	Send(text string) error
}

type Worker struct {
	pg     *storage.Postgres
	sender Sender
}

func NewWorker(pg *storage.Postgres, sender Sender) *Worker {
	return &Worker{pg: pg, sender: sender}
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	logger.Infof("telegram worker started")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.process()
		}
	}
}

func (w *Worker) process() {
	events, err := w.pg.ListUndeliveredEvents(20)
	if err != nil {
		logger.Errorf("telegram worker fetch error: %v", err)
		return
	}

	for _, e := range events {
		text := formatEvent(e)

		if err := w.sender.Send(text); err != nil {
			logger.Errorf("telegram send failed: %v", err)
			continue
		}

		_ = w.pg.MarkEventDelivered(e.ID)
	}
}

func formatEvent(e storage.Event) string {
	switch e.Type {
	case "new_port":
		return fmt.Sprintf(
			"🟢 *New open port*\nIP: %v\nPort: %v\nService: %v",
			e.Payload["ip"],
			e.Payload["port"],
			e.Payload["service"],
		)
	default:
		return fmt.Sprintf("event: %s", e.Type)
	}
}
