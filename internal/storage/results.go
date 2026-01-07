package storage

import (
	"time"
)

// DTO для WebUI (ТОЛЬКО то, что ждёт frontend)
type ResultRow struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	Service   string    `json:"service"`
	Banner    string    `json:"banner"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func (p *Postgres) ListResults() ([]ResultRow, error) {
	rows, err := p.db.Query(`
		SELECT
			h.ip::text,
			p.port,
			p.proto,
			COALESCE(p.service, 'unknown'),
			COALESCE(p.banner, ''),
			p.first_seen,
			p.last_seen
		FROM ports p
		JOIN hosts h ON h.id = p.host_id
		ORDER BY p.last_seen DESC
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ResultRow, 0, 128)

	for rows.Next() {
		var r ResultRow
		if err := rows.Scan(
			&r.IP,
			&r.Port,
			&r.Proto,
			&r.Service,
			&r.Banner,
			&r.FirstSeen,
			&r.LastSeen,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	return out, rows.Err()
}
