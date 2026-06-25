package database

func Migrate() error {

	query := `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		email TEXT UNIQUE,
		password TEXT
	);

	CREATE TABLE IF NOT EXISTS websites(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	domain TEXT,
	hash_id TEXT UNIQUE,
	api_key TEXT UNIQUE,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS logs(
	id INTEGER PRIMARY KEY AUTOINCREMENT,

	website_id INTEGER,

	api_key TEXT,

	ip TEXT,
	method TEXT,
	path TEXT,
	status INTEGER,

	user_agent TEXT,

	country TEXT,
	city TEXT,

	event_type TEXT,
	severity TEXT,

	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	website_id INTEGER,
	severity TEXT,
	message TEXT,
	ip TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


	`

	_, err := DB.Exec(query)
	return err
}
