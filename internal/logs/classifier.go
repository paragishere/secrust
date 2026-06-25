package logs

import "strings"

func Classify(path string) (string, string) {

	payload := strings.ToLower(path)

	// SQL Injection

	if strings.Contains(payload, "' or 1=1") ||
		strings.Contains(payload, "union select") ||
		strings.Contains(payload, "sleep(") {

		return "SQL_INJECTION", "HIGH"
	}

	// XSS

	if strings.Contains(payload, "<script") ||
		strings.Contains(payload, "onerror=") {

		return "XSS_ATTACK", "HIGH"
	}

	// Scanner

	if strings.Contains(payload, "/wp-admin") ||
		strings.Contains(payload, "/.env") ||
		strings.Contains(payload, "/phpmyadmin") {

		return "SCANNER_ACTIVITY", "MEDIUM"
	}

	// Login

	if strings.Contains(payload, "/login") {

		return "LOGIN_REQUEST", "INFO"
	}

	return "NORMAL", "INFO"
}
