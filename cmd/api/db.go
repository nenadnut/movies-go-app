package main

import (
	"database/sql"
	"log"

	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v4"
	_ "github.com/jackc/pgx/v4/stdlib" // these import are not explicitly but the sql lib requires an underlying driver which in this case
	// will be pgx
)

// sql.DB is a connection pool
func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (app *application) ConnectToDB() (*sql.DB, error) {
	connection, err := openDB(app.DSN)

	if err != nil {
		return nil, err
	}

	log.Println("Connected to Postgres")
	return connection, nil
}
