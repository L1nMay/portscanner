package storage

import "time"

func (p *Postgres) UpsertHost(ip string) (int64, error) {
	var id int64
	now := time.Now().UTC()

	err := p.db.QueryRow(`
		INSERT INTO hosts (ip, first_seen, last_seen)
		VALUES ($1::inet, $2, $2)
		ON CONFLICT (ip)
		DO UPDATE SET last_seen = EXCLUDED.last_seen
		RETURNING id
	`, ip, now).Scan(&id)

	return id, err
}
