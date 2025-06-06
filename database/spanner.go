package database

import (
	"database/sql"
	"fmt"
	"strings"

	"cloud.google.com/go/spanner"
	"github.com/golang-migrate/migrate/v4/database"
	migspanner "github.com/golang-migrate/migrate/v4/database/spanner"
	_ "github.com/googleapis/go-sql-spanner"
	"google.golang.org/grpc/codes"

	"github.com/orderlyvirtue/base/log"
)

func spannerConnection(_ log.Logger, cfg SpannerConfig, databaseName string) (*sql.DB, error) {
	db, err := sql.Open("spanner", fmt.Sprintf("projects/%s/instances/%s/databases/%s", cfg.Project, cfg.Instance, databaseName))
	if err != nil {
		return nil, err
	}

	return db, nil
}

func SpannerMigrationDriver(cfg SpannerConfig, databaseName string) (database.Driver, error) {
	clean := !cfg.DisableCleanStatements

	s := migspanner.Spanner{}
	return s.Open(fmt.Sprintf("spanner://projects/%s/instances/%s/databases/%s?x-migrations-table=spanner_schema_migrations&x-clean-statements=%t", cfg.Project, cfg.Instance, databaseName, clean))
}

// SpannerUniqueViolation returns true when the provided error matches the Spanner code
// for duplicate entries (violating a unique table constraint).
// Refer to https://cloud.google.com/spanner/docs/error-codes for Spanner error definitions,
// and https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto for error codes
func SpannerUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return spanner.ErrCode(err) == codes.AlreadyExists ||
		strings.Contains(err.Error(), "AlreadyExists")
}
