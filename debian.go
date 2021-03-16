package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
)

type debian struct {
	url   string
	name  string
	descr string
}

//NewDebian returns cve collector object for 'debian' source
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

func (d *debian) Descr() string {
	return d.descr
}

func (d *debian) Name() string {
	return d.name
}

func (d *debian) read(data *[]byte) (int, error) {
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

func (d *debian) parse(raw []byte) (*debCve, error) {
	data := debCve{}
	j := debResponse{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	for pkgName, cveMap := range j {
		for cveId, cveData := range cveMap {
			if _, ok := data[cveId]; !ok {
				data[cveId] = debPackage{pkgName: cveData}
			}
			data[cveId][pkgName] = cveData
		}
	}
	return &data, nil
}

func (d *debian) Collect() (interface{}, error) {
	data := make([]byte, 0)
	_, err := d.read(&data)
	if err != nil {
		return nil, err
	}
	resp, err := d.parse(data)
	return *resp, err
}

func (d *debian) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	cveName := "CVE-" + cveId
	path := fmt.Sprintf("[\"%s\"]", cveName)
	if pkgName != "" {
		path += fmt.Sprintf("[\"%s\"]", pkgName)
	}
	rlog.Debug(path)
	cveData, err := rdb.JSONGet(d.Name(), path)
	if err != nil {
		return nil, err
	}
	cveBytes, ok := cveData.([]byte)
	if !ok {
		return nil, errors.New("Can't case ....: ")
	}
	return cveBytes, nil
}
