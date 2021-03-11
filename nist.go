package main

import (
	"github.com/nitishm/go-rejson"
)

type nist struct {
	url   string
	name  string
	descr string
}

type nistCpeData struct {
	Uri                 string    `json:"cpe23Uri"`
	VersionEndExcluding string    `json:"versionEndExcluding,omitempty"`
	Cpes                []CpeName `json:"cpe_name,omitempty"`
}

type CpeName struct {
	Name string `json:"cpe23Uri"`
}

func NewNist() *nist {
	return &nist{
		sources["nist"],
		"nist",
		"NIST CPE data.",
	}
}

func (p *nist) Name() string {
	return p.name
}

func (p *nist) Descr() string {
	return p.descr
}

func (p *nist) Collect(rdb *rejson.Handler) (interface{}, error) {
	return nil, nil
}

func (p *nist) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	return nil, nil
}
