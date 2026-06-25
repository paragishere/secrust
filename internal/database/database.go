package database

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func Connect() error {
	var err error

	DB, err = sql.Open("sqlite", "./database/Secrust.db")

	if err != nil {
		return err
	}

	return DB.Ping()
}
