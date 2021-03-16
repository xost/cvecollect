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

type nistCpeList struct {
	Uri             string    `json:"cpe23Uri"`
	VersionStartInc string    `json:"versionStartIncluding,omitempty"`
	VersionStartExc string    `json:"versionStartExcluding,omitempty"`
	VersionEndInc   string    `json:"versionEndIncluding,omitempty"`
	VersionEndExc   string    `json:"versionEndExcluding,omitempty"`
	Cpes            []CpeName `json:"cpe_name,omitempty"`
}

type CpeName struct {
	Name string `json:"cpe23Uri"`
}

type nistCpeData struct {
	VersionStartInc string    `json:"versionStartIncluding,omitempty"`
	VersionStartExc string    `json:"versionStartExcluding,omitempty"`
	VersionEndInc   string    `json:"versionEndIncluding,omitempty"`
	VersionEndExc   string    `json:"versionEndExcluding,omitempty"`
	Cpes            []CpeName `json:"cpe_name,omitempty"`
}

//type nistCpe map[string]nistCpeData

//type CpeData struct {
//	Cpe23uri        Cpe23Uri   `json:"cpe23uri"`
//	VersionStartInc string     `json:"versionStartIncluding,omitempty"`
//	VersionStartExc string     `json:"versionStartExcluding,omitempty"`
//	VersionEndInc   string     `json:"versionEndIncluding,omitempty"`
//	VersionEndExc   string     `json:"versionEndExcluding,omitempty"`
//	CpeName         []Cpe23Uri `json:"cpe_name,omitempty"`
//}
//
//type Cpe23Uri struct {
//	Part     string
//	Vendor   string
//	Product  string
//	Version  string
//	Update   string
//	Edition  string
//	Language string
//}

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

func (p *nist) Collect() (interface{}, error) {
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
	data := make(map[string][]nistCpeList)
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return nil, err
	}
	//return []nistCpeList
	cpes := make(map[string][]nistCpeData)
	rlog.Debug(len(data["matches"]))
	for i, cpe23uri := range data["matches"] {
		if i%100 == 0 {
			rlog.Debug(i, "items is parsed")
		}
		if _, ok := cpes[cpe23uri.Uri]; ok {
			cpes[cpe23uri.Uri] = append(
				cpes[cpe23uri.Uri],
				nistCpeData{
					cpe23uri.VersionStartInc,
					cpe23uri.VersionStartExc,
					cpe23uri.VersionEndInc,
					cpe23uri.VersionEndExc,
					cpe23uri.Cpes,
				})
		}
		cpes[cpe23uri.Uri] = make([]nistCpeData, 0)
		cpes[cpe23uri.Uri] = append(
			cpes[cpe23uri.Uri],
			nistCpeData{
				cpe23uri.VersionStartInc,
				cpe23uri.VersionStartExc,
				cpe23uri.VersionEndInc,
				cpe23uri.VersionEndExc,
				cpe23uri.Cpes,
			})
	}
	rlog.Debug("RETURN")
	return cpes, nil
}

func (p *nist) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	path := fmt.Sprintf("[\"%s\"]", cveId)
	rawData, err := rdb.JSONGet(p.Name(), path)
	rlog.Debug(p.Name(), path)
	if err != nil {
		return nil, err
	}
	data, ok := rawData.([]byte)
	if !ok {
		rlog.Debug("***", data)
		return nil, errors.New("Can't cast to []byte")
	}
	return data, nil
}
