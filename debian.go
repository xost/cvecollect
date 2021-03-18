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

//reads big json from source url
func (d *debian) read(data *[]byte) (int, error) {
	resp, err := http.Get(d.url)
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

//parses json and transform data
func (d *debian) parse(raw []byte) (*debCve, error) {
	data := debCve{}
	j := debResponse{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	// cveID is first level key and packages is second level keys
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

//read big json, parse and transform
func (d *debian) Collect() (interface{}, error) {
	data := make([]byte, 0)
	//read big json
	_, err := d.read(&data)
	if err != nil {
		return nil, err
	}
	//unmarshal and transform
	resp, err := d.parse(data)
	return *resp, err
}

func (d *debian) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	cveName := "CVE-" + cveId //if cveID="2018-10906" then cveName="CVE-2018-10906"
	// generages path for redis query like ["CVE-2018-10906"]
	path := fmt.Sprintf("[\"%s\"]", cveName)
	if pkgName != "" {
		path += fmt.Sprintf("[\"%s\"]", pkgName)
	}
	rlog.Debug("redis path for", d.Name(), "is", path)
	//request to redis database
	cveData, err := rdb.JSONGet(d.Name(), path)
	if err != nil {
		return nil, err
	}
	//JSONGet returns interface{} so cast it to []byte
	cveBytes, ok := cveData.([]byte)
	if !ok {
		return nil, errors.New("Can't case redis response to []byte ")
	}
	return cveBytes, nil
}
