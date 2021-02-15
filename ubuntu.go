package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"golang.org/x/net/html"
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

func (p *ubuntu) SetURL(url string) {
	p.url = url
}

func (p *ubuntu) Read(data *[]byte) (int, error) {
	c := http.Client{}
	req, err := http.NewRequest("GET", p.url, nil)
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

func (p *ubuntu) Parse(raw []byte) (response, error) {
	j := response{}
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}
	return j, nil
}

func (p *ubuntu) listNodes(raw []byte) []string {
	r := bytes.NewReader(raw)
	t := html.NewTokenizer(r)
	for tokType := t.Next(); tokType != html.ErrorToken; tokType = t.Next() {
	}
	return []string{}
}
