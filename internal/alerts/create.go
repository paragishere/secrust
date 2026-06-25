package alerts

import "secrust/internal/database"

func CreateAlert(
	websiteID int,
	severity string,
	message string,
	ip string,
) {

	_, err := database.DB.Exec(
		`
		INSERT INTO alerts(
			website_id,
			severity,
			message,
			ip
		)
		VALUES(?,?,?,?)
		`,
		websiteID,
		severity,
		message,
		ip,
	)

	if err != nil {
		println("Alert Error:", err.Error())
	}
}
