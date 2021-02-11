package main

type cveData struct {
	Description string             `json:"description"`
	Releases    map[string]release `json:"releases"`
	Scope       string             `json:"scope"`
}

type release struct {
	FixedVersion string     `json:"fixed_version"`
	Repositories repository `json:"repositories"`
	Status       string     `json:"status"`
	Urgency      string     `json:"urgency"`
}

type response map[string]map[string]cveData
type repository map[string]string
