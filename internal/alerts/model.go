package alerts

type Alert struct {
	ID        int
	Severity  string
	Message   string
	IP        string
	WebsiteID int
	CreatedAt string
}
