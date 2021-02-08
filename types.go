package main

type CveData struct {
	Description string             `json:"description"`
	Releases    map[string]Release `json:"releases"`
	Scope       string             `json:"scope"`
}

type Release struct {
	FixedVersion string            `json:"fixed_version"`
	Repositories map[string]string `json:"repositories"`
	Status       string            `json:"status"`
	Urgency      string            `json:"urgency"`
}

type Response map[string]map[string]CveData
