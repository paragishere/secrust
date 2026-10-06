package database

func Migrate() error {

	query := `

	-- ==========================================
	-- USERS
	-- ==========================================

	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- ==========================================
	-- ORGANIZATIONS
	-- ==========================================

	CREATE TABLE IF NOT EXISTS organizations(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- ==========================================
	-- ORGANIZATION USERS
	-- ==========================================

	CREATE TABLE IF NOT EXISTS organization_users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		organization_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		role TEXT NOT NULL DEFAULT 'VIEWER',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

		UNIQUE(organization_id, user_id),

		FOREIGN KEY(organization_id)
			REFERENCES organizations(id)
			ON DELETE CASCADE,

		FOREIGN KEY(user_id)
			REFERENCES users(id)
			ON DELETE CASCADE
	);

	-- ==========================================
	-- WEBSITES
	-- ==========================================

	CREATE TABLE IF NOT EXISTS websites(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		organization_id INTEGER,
		domain TEXT NOT NULL,
		hash_id TEXT UNIQUE NOT NULL,
		api_key TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

		FOREIGN KEY(organization_id)
			REFERENCES organizations(id)
			ON DELETE CASCADE
	);

	-- ==========================================
	-- WEBSITE USERS
	-- ==========================================

	CREATE TABLE IF NOT EXISTS website_users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		website_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		permission TEXT NOT NULL DEFAULT 'VIEW',

		UNIQUE(website_id, user_id),

		FOREIGN KEY(website_id)
			REFERENCES websites(id)
			ON DELETE CASCADE,

		FOREIGN KEY(user_id)
			REFERENCES users(id)
			ON DELETE CASCADE
	);

	-- ==========================================
	-- LOGS
	-- ==========================================

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

		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

		FOREIGN KEY(website_id)
			REFERENCES websites(id)
			ON DELETE CASCADE
	);

	-- ==========================================
	-- ALERTS
	-- ==========================================

	CREATE TABLE IF NOT EXISTS alerts(
		id INTEGER PRIMARY KEY AUTOINCREMENT,

		website_id INTEGER,

		severity TEXT,
		message TEXT,
		ip TEXT,

		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

		FOREIGN KEY(website_id)
			REFERENCES websites(id)
			ON DELETE CASCADE
	);
CREATE TABLE IF NOT EXISTS invitations(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    invited_by INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    accepted_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    FOREIGN KEY(invited_by)
        REFERENCES users(id)
        ON DELETE CASCADE
);
	`

	_, err := DB.Exec(query)

	return err
}
func MigrateExistingData() error {

	// ==========================================
	// Find users without organization
	// ==========================================

	rows, err := DB.Query(`
		SELECT
			u.id,
			u.name
		FROM users u
		LEFT JOIN organization_users ou
			ON ou.user_id = u.id
		WHERE ou.user_id IS NULL
	`)

	if err != nil {
		return err
	}

	defer rows.Close()

	type userData struct {
		ID   int
		Name string
	}

	var users []userData

	for rows.Next() {

		var u userData

		if err := rows.Scan(
			&u.ID,
			&u.Name,
		); err != nil {
			return err
		}

		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	// ==========================================
	// Create organization for old users
	// ==========================================

	for _, u := range users {

		tx, err := DB.Begin()

		if err != nil {
			return err
		}

		organizationName :=
			u.Name + "'s Organization"

		result, err := tx.Exec(`
			INSERT INTO organizations(name)
			VALUES(?)
		`, organizationName)

		if err != nil {
			tx.Rollback()
			return err
		}

		orgID64, err := result.LastInsertId()

		if err != nil {
			tx.Rollback()
			return err
		}

		orgID := int(orgID64)

		// ======================================
		// Make old user SUPER_ADMIN
		// ======================================

		_, err = tx.Exec(`
			INSERT INTO organization_users(
				organization_id,
				user_id,
				role
			)
			VALUES(?,?,?)
		`,
			orgID,
			u.ID,
			"SUPER_ADMIN",
		)

		if err != nil {
			tx.Rollback()
			return err
		}

		// ======================================
		// Assign old websites
		// ======================================

		_, err = tx.Exec(`
			UPDATE websites
			SET organization_id=?
			WHERE user_id=?
			AND organization_id IS NULL
		`,
			orgID,
			u.ID,
		)

		if err != nil {
			tx.Rollback()
			return err
		}

		// ======================================
		// Add website permissions
		// ======================================

		_, err = tx.Exec(`
			INSERT OR IGNORE INTO website_users(
				website_id,
				user_id,
				permission
			)
			SELECT
				id,
				?,
				'ADMIN'
			FROM websites
			WHERE user_id=?
		`,
			u.ID,
			u.ID,
		)

		if err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}
func MigrateUserManagement() error {

	rows, err := DB.Query(`
		PRAGMA table_info(users)
	`)

	if err != nil {
		return err
	}

	defer rows.Close()

	hasStatus := false

	for rows.Next() {

		var (
			cid      int
			name     string
			dataType string
			notNull  int
			defaultV interface{}
			primary  int
		)

		if err := rows.Scan(
			&cid,
			&name,
			&dataType,
			&notNull,
			&defaultV,
			&primary,
		); err != nil {
			return err
		}

		if name == "status" {
			hasStatus = true
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	if !hasStatus {

		_, err := DB.Exec(`
			ALTER TABLE users
			ADD COLUMN status TEXT DEFAULT 'ACTIVE'
		`)

		if err != nil {
			return err
		}
	}

	return nil
}
