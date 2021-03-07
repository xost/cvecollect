package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/nitishm/go-rejson"
)

type debian struct {
	url   string
	name  string
	descr string
}

func NewDebian() *debian {
	return &debian{
		sources["debian"],
		"debian",
		"Debian CVE data.",
	}
}

func (d *debian) setURL(url string) {
	d.url = url
}

func (p *debian) Descr() string {
	return p.descr
}

func (p *debian) Name() string {
	return p.name
}

func (d *debian) Read(data *[]byte) (int, error) {
	c := http.Client{}
	req, err := http.NewRequest("GET", d.url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data1, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	*data = data1[:]
	return len(*data), nil
}

func (d *debian) parse(raw []byte) (*Cve, error) {
	data := Cve{}
	j := Response{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	for pkgName, cveMap := range j {
		for cveId, cveData := range cveMap {
			if _, ok := data[cveId]; !ok {
				data[cveId] = Package{pkgName: cveData}
			}
			data[cveId][pkgName] = cveData
		}
	}
	return &data, nil
}

func (p *debian) Collect(rdb *rejson.Handler) (interface{}, error) {
	data := make([]byte, 0)
	_, err := p.Read(&data) //do not handle err be cause anyway i return reps empty or not and err nil or not
	if err != nil {
		return nil, err
	}
	resp, err := p.parse(data)
	return *resp, err
}

func (p *debian) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	cveName := "CVE-" + cveId
	path := fmt.Sprintf("[\"%s\"]", cveName)
	if pkgName != "" {
		path += fmt.Sprintf("[\"%s\"]", pkgName)
	}
	cveData, err := rdb.JSONGet(p.Name(), path)
	if err != nil {
		return nil, err
	}
	cveBytes, ok := cveData.([]byte)
	if !ok {
		return nil, errors.New("Can't case ....")
	}
	return cveBytes, nil
}
