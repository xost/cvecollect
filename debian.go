package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
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

func (d *debian) parse(raw []byte) (*Response, error) {
	j := Response{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (p *debian) Collect() (resp *Response, err error) {
	resp = &Response{}
	data := make([]byte, 0)
	_, err = p.Read(&data) //do not handle err be cause anyway i return reps empty or not and err nil or not
	if err != nil {
		return
	}
	resp, err = p.parse(data)
	return
}
