// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
)

var (
	// CreateTableRuntimeFilterDataStmt holds the create statement for table `runtime_filter_data`.
	CreateTableRuntimeFilterDataStmt = &postgres.CreateStmts{
		GormModel: (*RuntimeFilterData)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// RuntimeFilterDataSchema is the go schema for table `runtime_filter_data`.
	RuntimeFilterDataSchema = func() *walker.Schema {
		schema := GetSchemaForTable("runtime_filter_data")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.RuntimeFilterData)(nil)), "runtime_filter_data")
		schema.ScopingResource = resources.Administration
		RegisterTable(schema, CreateTableRuntimeFilterDataStmt)
		return schema
	}()
)

const (
	// RuntimeFilterDataTableName specifies the name of the table in postgres.
	RuntimeFilterDataTableName = "runtime_filter_data"
)

// RuntimeFilterData holds the Gorm model for Postgres table `runtime_filter_data`.
type RuntimeFilterData struct {
	ID         string `gorm:"column:id;type:varchar;primaryKey"`
	Serialized []byte `gorm:"column:serialized;type:bytea"`
}