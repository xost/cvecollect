package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type debian struct {
	url string
}

func NewDebian() *debian {
	return &debian{
		sources["debian"],
	}
}

func (d *debian) SetURL(url string) {
	d.url = url
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

func (d *debian) Parse(raw []byte) (Response, error) {
	j := Response{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	return j, nil
}
