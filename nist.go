package main

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
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
	//get gzip file
	req, err := http.NewRequest("GET", p.url, nil)
	if err != nil {
		return nil, err
	}
	c := http.Client{}
	rlog.Info("Fetching nist file")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	//decompress gzip file
	rlog.Info("Decompressing nist file")
	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	rawData, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	//parse file to struct
	data := make(map[string][]nistCpeData)
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return nil, err
	}
	//return []nistCpeData
	return data["matches"], nil
}

func (p *nist) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	path := fmt.Sprintf("[\"%s\"]", cveId)
	rawData, err := rdb.JSONGet(p.Name(), path)
	if err != nil {
		return nil, err
	}
	data, ok := rawData.([]byte)
	if !ok {
		return nil, errors.New("Can't cast to []byte")
	}
	return data, nil
}
