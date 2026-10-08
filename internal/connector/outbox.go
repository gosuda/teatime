package connector

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"tokenhub/internal/model"
	"tokenhub/internal/privatefs"
)

type Outbox struct{ db *sql.DB }

func OpenOutbox(dir string) (*Outbox, error) {
	if err := privatefs.Dir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "outbox.db")
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := privatefs.File(p); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS publications(service TEXT PRIMARY KEY,local_key TEXT NOT NULL,route TEXT NOT NULL,provider TEXT NOT NULL,server_name TEXT NOT NULL,since TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries(service TEXT NOT NULL,id TEXT NOT NULL,version INTEGER NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,pending INTEGER NOT NULL,PRIMARY KEY(service,id));`)
	if err == nil {
		err = privatefs.File(path)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Outbox{db: db}, nil
}
func (o *Outbox) Close() error { return o.db.Close() }

// PinPublication keeps the locally accepted scope immutable. A Hub response
// cannot backdate a publication or repurpose its identifier for another route.
func (o *Outbox) PinPublication(ctx context.Context, s model.Service) (time.Time, error) {
	since := time.Now().UTC()
	if s.PublishedAt.After(since) {
		since = s.PublishedAt
	}
	if s.PublishedAt.IsZero() || since.After(time.Now().Add(5*time.Minute)) {
		return time.Time{}, errors.New("publication_time_invalid")
	}
	_, err := o.db.ExecContext(ctx, "INSERT INTO publications VALUES(?,?,?,?,?,?) ON CONFLICT(service) DO NOTHING", s.ID, s.Key, s.RouteID, s.Provider, s.ServerName, since.Format(time.RFC3339Nano))
	if err != nil {
		return time.Time{}, err
	}
	var key, route, provider, server, pinned string
	if err = o.db.QueryRowContext(ctx, "SELECT local_key,route,provider,server_name,since FROM publications WHERE service=?", s.ID).Scan(&key, &route, &provider, &server, &pinned); err != nil {
		return time.Time{}, err
	}
	if key != s.Key || route != s.RouteID || provider != s.Provider || server != s.ServerName {
		return time.Time{}, errors.New("publication_scope_changed")
	}
	return time.Parse(time.RFC3339Nano, pinned)
}
func (o *Outbox) Enqueue(ctx context.Context, service string, records []model.Usage) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, u := range records {
		if u.Validate() != nil {
			return errors.New("invalid_usage")
		}
		raw, _ := json.Marshal(u)
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		_, err = tx.Exec(`INSERT INTO deliveries VALUES(?,?,1,?,?,1) ON CONFLICT(service,id) DO UPDATE SET version=deliveries.version+1,hash=excluded.hash,payload=excluded.payload,pending=1 WHERE excluded.hash<>deliveries.hash`, service, u.ID, hash, string(raw))
		if err != nil {
			return err
		}
	}
	var count, size int64
	if err = tx.QueryRow("SELECT count(*),COALESCE(sum(length(payload)),0) FROM deliveries WHERE pending=1").Scan(&count, &size); err != nil {
		return err
	}
	if count > 100000 || size > 64<<20 {
		return errors.New("outbox_full")
	}
	return tx.Commit()
}
func (o *Outbox) Pending(ctx context.Context) ([]model.Report, error) {
	rows, err := o.db.QueryContext(ctx, "SELECT service,version,payload FROM deliveries WHERE pending=1 ORDER BY service,id LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.Report{}
	for rows.Next() {
		var v model.Report
		var raw string
		if rows.Scan(&v.ServiceID, &v.Version, &raw) != nil || json.Unmarshal([]byte(raw), &v.Usage) != nil {
			return nil, errors.New("outbox_corrupt")
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
func (o *Outbox) Ack(ctx context.Context, records []model.Report) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, v := range records {
		if _, err = tx.Exec("UPDATE deliveries SET pending=0 WHERE service=? AND id=? AND version=?", v.ServiceID, v.Usage.ID, v.Version); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (o *Outbox) Deliver(ctx context.Context, a *API) error {
	for {
		records, err := o.Pending(ctx)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}
		var ack struct {
			Accepted int `json:"accepted"`
		}
		if err = a.Call(ctx, "POST", "/api/connector/usage", map[string]any{"reports": records}, &ack); err != nil {
			return err
		}
		if ack.Accepted != len(records) {
			return errors.New("usage_ack_invalid")
		}
		if err = o.Ack(ctx, records); err != nil {
			return err
		}
	}
}
