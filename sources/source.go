package sources

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
)

type DataSource interface {
	GetData(key string) ([]byte, error)
	GetResourceId(key string) string
}


type SourceFactory = func(jsonData []byte) (DataSource, error)
var sourceFactories = make(map[string]SourceFactory)

func RegisterDataSourceFactory(sourceType string, factory SourceFactory) {
	sourceFactories[sourceType] = factory
}

type DataSourceConfiguration struct {
	Type string
	Config json.RawMessage
}

func NewDataSource(config DataSourceConfiguration) (source DataSource, err error) {
	if sourceFactory, found := sourceFactories[config.Type]; found {
		dataSource, err := sourceFactory(config.Config)
		if err != nil {
			return nil, errors.Wrap(err, "creating data source")
		}
		return dataSource, nil
	}
	return nil, errors.New(fmt.Sprintf("no factory for source type '%s'", config.Type))
}