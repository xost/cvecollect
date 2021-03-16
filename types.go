package main

import "github.com/nitishm/go-rejson"

//type CveData1 struct {
//	Description string             `json:"description"`
//	Releases    map[string]Release `json:"releases"`
//	Scope       string             `json:"scope"`
//}

type debCveData struct {
	Description string                `json:"description"`
	Releases    map[string]debRelease `json:"releases"`
	Scope       string                `json:"scope"`
}

type debRelease struct {
	FixedVersion string        `json:"fixed_version"`
	Repositories debRepository `json:"repositories"`
	Status       string        `json:"status"`
	Urgency      string        `json:"urgency"`
}

//map["package name"]["cveid"]CveData
type debResponse map[string]map[string]debCveData
type debRepository map[string]string

//map["package name"]CveData
type debPackage map[string]debCveData

//map["CveId"]["PackageName"]CveData
type debCve map[string]debPackage

type Collector interface {
	Collect() (interface{}, error)
	Query(string, string, *rejson.Handler) ([]byte, error)
	Name() string
	Descr() string
}
