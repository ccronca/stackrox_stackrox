// Code generated by pg-bindings generator. DO NOT EDIT.
package postgres

import (
	"context"

	"github.com/stackrox/rox/generated/storage"
	pkgSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/pkg/logging"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sync"
)

const (
	baseTable = "configs"

	getStmt    = "SELECT serialized FROM configs LIMIT 1"
	deleteStmt = "DELETE FROM configs"
)

var (
	log    = logging.LoggerForModule()
	schema = pkgSchema.ConfigsSchema
)

type Store interface {
	Get(ctx context.Context) (*storage.Config, bool, error)
	Upsert(ctx context.Context, obj *storage.Config) error
	Delete(ctx context.Context) error
}

type storeImpl struct {
	db    postgres.DB
	mutex sync.Mutex
}

// New returns a new Store instance using the provided sql instance.
func New(db postgres.DB) Store {
	return &storeImpl{
		db: db,
	}
}

func insertIntoConfigs(ctx context.Context, tx *postgres.Tx, obj *storage.Config) error {
	serialized, marshalErr := obj.Marshal()
	if marshalErr != nil {
		return marshalErr
	}

	values := []interface{}{
		// parent primary keys start
		serialized,
	}

	finalStr := "INSERT INTO configs (serialized) VALUES($1)"
	_, err := tx.Exec(ctx, finalStr, values...)
	if err != nil {
		return err
	}
	return nil
}

func (s *storeImpl) Upsert(ctx context.Context, obj *storage.Config) error {
	return pgutils.Retry(func() error {
		return s.retryableUpsert(ctx, obj)
	})
}

func (s *storeImpl) retryableUpsert(ctx context.Context, obj *storage.Config) error {
	conn, release, err := s.acquireConn(ctx, ops.Get, "Config")
	if err != nil {
		return err
	}
	defer release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, deleteStmt); err != nil {
		return err
	}

	if err := insertIntoConfigs(ctx, tx, obj); err != nil {
		if err := tx.Rollback(ctx); err != nil {
			return err
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// Get returns the object, if it exists from the store
func (s *storeImpl) Get(ctx context.Context) (*storage.Config, bool, error) {
	return pgutils.Retry3(func() (*storage.Config, bool, error) {
		return s.retryableGet(ctx)
	})
}

func (s *storeImpl) retryableGet(ctx context.Context) (*storage.Config, bool, error) {
	conn, release, err := s.acquireConn(ctx, ops.Get, "Config")
	if err != nil {
		return nil, false, err
	}
	defer release()

	row := conn.QueryRow(ctx, getStmt)
	var data []byte
	if err := row.Scan(&data); err != nil {
		return nil, false, pgutils.ErrNilIfNoRows(err)
	}

	var msg storage.Config
	if err := msg.Unmarshal(data); err != nil {
		return nil, false, err
	}
	return &msg, true, nil
}

func (s *storeImpl) acquireConn(ctx context.Context, op ops.Op, typ string) (*postgres.Conn, func(), error) {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.Release, nil
}

// Delete removes the singleton from the store
func (s *storeImpl) Delete(ctx context.Context) error {
	return pgutils.Retry(func() error {
		return s.retryableDelete(ctx)
	})
}

func (s *storeImpl) retryableDelete(ctx context.Context) error {
	conn, release, err := s.acquireConn(ctx, ops.Remove, "Config")
	if err != nil {
		return err
	}
	defer release()

	if _, err := conn.Exec(ctx, deleteStmt); err != nil {
		return err
	}
	return nil
}

// Used for Testing

func Destroy(ctx context.Context, db postgres.DB) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS configs CASCADE")
}