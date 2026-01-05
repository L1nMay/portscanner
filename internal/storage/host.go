package storage

func (p *Postgres) UpsertHost(ip string) (int64, error) {
	var id int64
	err := p.db.QueryRow(`
		INSERT INTO hosts (ip, first_seen, last_seen)
		VALUES ($1, now(), now())
		ON CONFLICT (ip)
		DO UPDATE SET last_seen = now()
		RETURNING id
	`, ip).Scan(&id)
	return id, err
}
