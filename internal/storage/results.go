package storage

import "github.com/L1nMay/portscanner/internal/model"

func (p *Postgres) ListResults() ([]*model.ScanResult, error) {
	rows, err := p.db.Query(`
		SELECT
			h.ip,
			p.port,
			p.proto,
			p.service,
			p.banner,
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

	var res []*model.ScanResult

	for rows.Next() {
		var r model.ScanResult
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
		res = append(res, &r)
	}

	return res, nil
}
