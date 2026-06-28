package database

import (
	"database/sql"
	"os"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func Connect() error {
	var err error

	// Create the folder if it doesn't exist
	if err := os.MkdirAll("data", 0755); err != nil {
		return err
	}

	DB, err = sql.Open("sqlite", "data/Secrust.db")
	if err != nil {
		return err
	}

	return DB.Ping()
}
