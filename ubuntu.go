package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type ubuntu struct {
	url   string
	paths []string
}

func NewUbuntu() *ubuntu {
	return &ubuntu{
		sources["ubuntu"],
		[]string{"/tree/active", "/tree/retired"},
	}
}

func (d *ubuntu) SetURL(url string) {
	d.url = url
}

func (d *ubuntu) Read(data *[]byte) (int, error) {
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

func (d *ubuntu) Parse(raw []byte) (response, error) {
	j := response{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	return j, nil
}
