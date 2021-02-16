package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
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

func (p *ubuntu) listNodes(raw []byte) ([]string, error) {
	rdr := bytes.NewReader(raw)
	doc := html.NewTokenizer(rdr)
	rslt := make([]string, 0)
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tknType == html.StartTagToken {
			if tkn.DataAtom != atom.A {
				continue
			}
			for _, attr := range tkn.Attr {
				if attr.Key == "href" {
					href := attr.Val
					tknType = doc.Next()
					if tknType == html.TextToken {
						tkn = doc.Token()
						if strings.HasPrefix(tkn.Data, "CVE-") {
							fmt.Println(href, " - ", tkn.Data)
						}
					}
				}
			}
		}
	}
	return rslt, nil
}

func (u *ubuntu) readUrl(url string) ([]byte, error) {
	c := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (u *ubuntu) ParseRaw(raw []byte) (pkgs []string, cve cveData, err error) {
	rdr := bytes.NewReader(raw)
	doc := html.NewTokenizer(rdr)
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tknType == html.StartTagToken {
			if tkn.DataAtom != atom.Code {
				continue
			}
			data := tkn.Data
			cveid, cve, err := u.getCve(data)
			if err != nil {
				return "", cveData{}, err
			}
			return cveid, cve, nil
		}
	}
	return "", cveData{}, nil
}

func (u *ubuntu) getCve(data string) (string, cveData, error) {
}
