package storage

import (
	"encoding/json"
	"time"
)

// Event — событие для Telegram / audit / future hooks
type Event struct {
	ID        int64                  `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]any         `json:"payload"`
	CreatedAt time.Time              `json:"created_at"`
	Delivered bool                   `json:"delivered"`
}

// AddEvent — сохраняет новое событие
func (p *Postgres) AddEvent(eventType string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = p.db.Exec(`
		INSERT INTO events (type, payload, created_at, delivered)
		VALUES ($1, $2, $3, false)
	`, eventType, data, time.Now().UTC())

	return err
}

// ListUndeliveredEvents — события, которые ещё не отправлены
func (p *Postgres) ListUndeliveredEvents(limit int) ([]Event, error) {
	rows, err := p.db.Query(`
		SELECT id, type, payload, created_at, delivered
		FROM events
		WHERE delivered = false
		ORDER BY id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event

	for rows.Next() {
		var e Event
		var payload []byte

		if err := rows.Scan(
			&e.ID,
			&e.Type,
			&payload,
			&e.CreatedAt,
			&e.Delivered,
		); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(payload, &e.Payload); err != nil {
			return nil, err
		}

		out = append(out, e)
	}

	return out, nil
}

// MarkEventDelivered — помечает событие как доставленное
func (p *Postgres) MarkEventDelivered(id int64) error {
	_, err := p.db.Exec(`
		UPDATE events
		SET delivered = true
		WHERE id = $1
	`, id)

	return err
}
