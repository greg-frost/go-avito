package postgres

import (
	"database/sql"
	"fmt"
)

type ConnectionParams struct {
	Host     string
	DbName   string
	User     string
	Password string
	Port     string
}

func connect(params ConnectionParams) (*sql.DB, error) {
	if params.Host == "" {
		params.Host = "localhost"
	}
	if params.Port == "" {
		params.Port = "5432"
	}

	dsn := fmt.Sprintf(
		"host='%s' user='%s' password='%s' dbname='%s' port='%s' sslmode='disable'",
		params.Host, params.User, params.Password, params.DbName, params.Port,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
