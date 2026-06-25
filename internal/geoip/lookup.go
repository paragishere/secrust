package geoip

import (
	"encoding/json"
	"net/http"
)

type GeoResponse struct {
	Country string `json:"country"`
	City    string `json:"city"`
}

func Lookup(ip string) (string, string) {

	resp, err := http.Get(
		"http://ip-api.com/json/" + ip,
	)

	if err != nil {
		return "Unknown", "Unknown"
	}

	defer resp.Body.Close()

	var data GeoResponse

	json.NewDecoder(resp.Body).
		Decode(&data)

	return data.Country, data.City
}
