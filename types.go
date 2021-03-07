package main

import "github.com/nitishm/go-rejson"

//type CveData1 struct {
//	Description string             `json:"description"`
//	Releases    map[string]Release `json:"releases"`
//	Scope       string             `json:"scope"`
//}

type CveData struct {
	Description string             `json:"description"`
	Releases    map[string]Release `json:"releases"`
	Scope       string             `json:"scope"`
}

type Release struct {
	FixedVersion string     `json:"fixed_version"`
	Repositories Repository `json:"repositories"`
	Status       string     `json:"status"`
	Urgency      string     `json:"urgency"`
}

//map["package name"]["cveid"]CveData
type Response map[string]map[string]CveData
type Repository map[string]string

//map["package name"]CveData
type Package map[string]CveData

//map["CveId"]["PackageName"]CveData
type Cve map[string]map[string]CveData

type Collector interface {
	Collect(*rejson.Handler) (interface{}, error)
	Query(string, string, *rejson.Handler) ([]byte, error)
	Name() string
	Descr() string
}
