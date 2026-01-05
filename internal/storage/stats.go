package storage

func (p *Postgres) GetStats() (*Stats, error) {
	var s Stats

	err := p.db.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM ports),
			(SELECT COUNT(*) FROM hosts)
	`).Scan(&s.TotalFindings, &s.UniqueHosts)

	if err != nil {
		return nil, err
	}

	return &s, nil
}
