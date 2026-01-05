package storage

import "encoding/json"

func (p *Postgres) AddEvent(eventType string, payload any) error {
	b, _ := json.Marshal(payload)
	_, err := p.db.Exec(`
		INSERT INTO events (type, payload)
		VALUES ($1, $2)
	`, eventType, b)
	return err
}
