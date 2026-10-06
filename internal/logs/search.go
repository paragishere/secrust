package logs

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/website"
)

type QueryParser struct {
	tokens []string
	pos    int
	args   []interface{}
}

type QueryResult struct {
	SQL  string
	Args []interface{}
}

func SearchLogs(c *gin.Context) {

	hash := c.Param("hash")

	session := sessions.Default(c)
	userID := session.Get("user_id")

	if userID == nil {
		c.Redirect(302, "/login")
		return
	}

	websiteID, domain, err :=
		website.GetWebsiteByHashAndUser(hash, userID)

	if err != nil {
		c.JSON(403, gin.H{
			"error": "Access denied",
		})
		return
	}

	query := strings.TrimSpace(c.Query("q"))

	var rows *sql.Rows

	// ========================================================
	// Empty Search
	// ========================================================

	if query == "" {

		rows, err = database.DB.Query(`
			SELECT
				id,
				website_id,
				api_key,
				ip,
				method,
				path,
				status,
				user_agent,
				country,
				city,
				event_type,
				severity,
				created_at
			FROM logs
			WHERE website_id=?
			ORDER BY id DESC
			LIMIT 500
		`, websiteID)

		// ========================================================
		// SQuery
		// ========================================================

	} else if isSQuery(query) {

		result, buildErr := BuildSQuery(
			query,
			websiteID,
		)

		if buildErr != nil {

			c.HTML(400, "logs.html", gin.H{
				"logs":   nil,
				"hash":   hash,
				"domain": domain,
				"error":  buildErr.Error(),
				"query":  query,
			})

			return
		}

		rows, err = database.DB.Query(
			result.SQL,
			result.Args...,
		)

		// ========================================================
		// Normal Search
		// ========================================================

	} else {

		search := "%" + query + "%"

		rows, err = database.DB.Query(`
			SELECT
				id,
				website_id,
				api_key,
				ip,
				method,
				path,
				status,
				user_agent,
				country,
				city,
				event_type,
				severity,
				created_at
			FROM logs
			WHERE website_id=?
			AND (
				ip LIKE ?
				OR method LIKE ?
				OR path LIKE ?
				OR country LIKE ?
				OR city LIKE ?
				OR event_type LIKE ?
				OR severity LIKE ?
			)
			ORDER BY id DESC
			LIMIT 500
		`,
			websiteID,
			search,
			search,
			search,
			search,
			search,
			search,
			search,
		)
	}

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	defer rows.Close()

	var logs []Log

	for rows.Next() {

		var l Log

		err := rows.Scan(
			&l.ID,
			&l.WebsiteID,
			&l.APIKey,
			&l.IP,
			&l.Method,
			&l.Path,
			&l.Status,
			&l.UserAgent,
			&l.Country,
			&l.City,
			&l.EventType,
			&l.Severity,
			&l.CreatedAt,
		)

		if err != nil {
			continue
		}

		logs = append(logs, l)
	}

	if err := rows.Err(); err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.HTML(200, "logs.html", gin.H{
		"logs":   logs,
		"hash":   hash,
		"domain": domain,
		"query":  query,
	})
}

// ============================================================
// SQuery Detection
// ============================================================

func isSQuery(query string) bool {

	lower := strings.ToLower(query)

	fields := []string{
		"ip:",
		"path:",
		"method:",
		"status:",
		"country:",
		"city:",
		"event:",
		"severity:",
	}

	for _, field := range fields {

		if strings.Contains(lower, field) {
			return true
		}
	}

	upper := strings.ToUpper(query)

	return strings.Contains(upper, " AND ") ||
		strings.Contains(upper, " OR ") ||
		strings.HasPrefix(upper, "NOT ")
}

// ============================================================
// Build SQuery
// ============================================================

func BuildSQuery(
	query string,
	websiteID int,
) (*QueryResult, error) {

	tokens := tokenize(query)

	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty query")
	}

	parser := &QueryParser{
		tokens: tokens,
	}

	condition, err := parser.parseExpression()

	if err != nil {
		return nil, err
	}

	if parser.pos < len(parser.tokens) {

		return nil, fmt.Errorf(
			"unexpected token: %s",
			parser.tokens[parser.pos],
		)
	}

	sqlQuery := `
		SELECT
			id,
			website_id,
			api_key,
			ip,
			method,
			path,
			status,
			user_agent,
			country,
			city,
			event_type,
			severity,
			created_at
		FROM logs
		WHERE website_id=?
		AND (` + condition + `)
		ORDER BY id DESC
		LIMIT 500
	`

	args := []interface{}{websiteID}
	args = append(args, parser.args...)

	return &QueryResult{
		SQL:  sqlQuery,
		Args: args,
	}, nil
}

// ============================================================
// OR
// ============================================================

func (p *QueryParser) parseExpression() (string, error) {

	left, err := p.parseAND()

	if err != nil {
		return "", err
	}

	for p.match("OR") {

		right, err := p.parseAND()

		if err != nil {
			return "", err
		}

		left = "(" + left + " OR " + right + ")"
	}

	return left, nil
}

// ============================================================
// AND
// ============================================================

func (p *QueryParser) parseAND() (string, error) {

	left, err := p.parseNOT()

	if err != nil {
		return "", err
	}

	for p.match("AND") {

		right, err := p.parseNOT()

		if err != nil {
			return "", err
		}

		left = "(" + left + " AND " + right + ")"
	}

	return left, nil
}

// ============================================================
// NOT
// ============================================================

func (p *QueryParser) parseNOT() (string, error) {

	if p.match("NOT") {

		expr, err := p.parseNOT()

		if err != nil {
			return "", err
		}

		return "(NOT " + expr + ")", nil
	}

	return p.parsePrimary()
}

// ============================================================
// Primary
// ============================================================

func (p *QueryParser) parsePrimary() (string, error) {

	if p.pos >= len(p.tokens) {
		return "", fmt.Errorf("unexpected end of query")
	}

	token := p.tokens[p.pos]

	if token == "(" {

		p.pos++

		expr, err := p.parseExpression()

		if err != nil {
			return "", err
		}

		if p.pos >= len(p.tokens) ||
			p.tokens[p.pos] != ")" {

			return "", fmt.Errorf(
				"missing closing parenthesis",
			)
		}

		p.pos++

		return "(" + expr + ")", nil
	}

	if token == ")" {

		return "", fmt.Errorf(
			"unexpected closing parenthesis",
		)
	}

	p.pos++

	return p.parseCondition(token)
}

// ============================================================
// Condition
// ============================================================

func (p *QueryParser) parseCondition(
	token string,
) (string, error) {

	parts := strings.SplitN(
		token,
		":",
		2,
	)

	if len(parts) != 2 {

		return "", fmt.Errorf(
			"invalid SQuery condition: %s",
			token,
		)
	}

	field := strings.ToLower(
		strings.TrimSpace(parts[0]),
	)

	value := strings.Trim(
		strings.TrimSpace(parts[1]),
		`"'`,
	)

	if value == "" {

		return "", fmt.Errorf(
			"empty value for %s",
			field,
		)
	}

	switch field {

	case "ip":

		p.args = append(
			p.args,
			"%"+value+"%",
		)

		return "ip LIKE ?", nil

	case "path":

		p.args = append(
			p.args,
			"%"+value+"%",
		)

		return "path LIKE ?", nil

	case "method":

		p.args = append(
			p.args,
			value,
		)

		return "method = ?", nil

	case "status":

		status, err := strconv.Atoi(value)

		if err != nil {

			return "", fmt.Errorf(
				"invalid status: %s",
				value,
			)
		}

		p.args = append(
			p.args,
			status,
		)

		return "status = ?", nil

	case "country":

		p.args = append(
			p.args,
			"%"+value+"%",
		)

		return "country LIKE ?", nil

	case "city":

		p.args = append(
			p.args,
			"%"+value+"%",
		)

		return "city LIKE ?", nil

	case "event":

		p.args = append(
			p.args,
			value,
		)

		return "event_type = ?", nil

	case "severity":

		value = strings.ToUpper(value)

		switch value {

		case "INFO",
			"LOW",
			"MEDIUM",
			"HIGH",
			"CRITICAL":

			p.args = append(
				p.args,
				value,
			)

			return "severity = ?", nil

		default:

			return "", fmt.Errorf(
				"invalid severity: %s",
				value,
			)
		}

	default:

		return "", fmt.Errorf(
			"unknown field: %s",
			field,
		)
	}
}

// ============================================================
// Tokenizer
// ============================================================

func tokenize(query string) []string {

	query = strings.ReplaceAll(
		query,
		"(",
		" ( ",
	)

	query = strings.ReplaceAll(
		query,
		")",
		" ) ",
	)

	raw := strings.Fields(query)

	var tokens []string

	for _, token := range raw {

		switch strings.ToUpper(token) {

		case "AND":
			tokens = append(tokens, "AND")

		case "OR":
			tokens = append(tokens, "OR")

		case "NOT":
			tokens = append(tokens, "NOT")

		default:
			tokens = append(tokens, token)
		}
	}

	return tokens
}

// ============================================================
// Match
// ============================================================

func (p *QueryParser) match(
	expected string,
) bool {

	if p.pos >= len(p.tokens) {
		return false
	}

	if p.tokens[p.pos] == expected {

		p.pos++

		return true
	}

	return false
}
