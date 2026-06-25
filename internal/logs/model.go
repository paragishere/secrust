package logs

type Log struct {
	ID        int `json:"id"`
	WebsiteID int `json:"website_id"`

	APIKey string `json:"api_key"`

	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`

	UserAgent string `json:"user_agent"`

	Country string `json:"country"`
	City    string `json:"city"`

	EventType string `json:"event_type"`
	Severity  string `json:"severity"`

	CreatedAt string `json:"created_at"`
}
