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

func (p *ubuntu) Parse(raw []byte) (Response, error) {
	j := Response{}
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

//func (u *ubuntu) ParseRaw(raw []byte) (pkgs []string, cve CveData, err error) {
//	rdr := bytes.NewReader(raw)
//	doc := html.NewTokenizer(rdr)
//	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
//		tkn := doc.Token()
//		if tknType == html.StartTagToken {
//			if tkn.DataAtom != atom.Code {
//				continue
//			}
//			data := tkn.Data
//			cveid, cve, err := u.getCve(data)
//			if err != nil {
//				return "", CveData{}, err
//			}
//			return cveid, cve, nil
//		}
//	}
//	return "", CveData{}, nil
//}

func (u *ubuntu) parseText(data string) (Response, error) {
	lines := strings.Split(data, "\n")
	pkgs := Response{}
	descr := ""
	urgency := ""
	cveid := ""
	cve := make(map[string]CveData)
	releases := []Release{}
	for i := 0; i < len(lines); i++ { //got cveid
		if strings.HasPrefix(lines[i], "Candidate:") { //maybe should add ' && cveid=="" '
			cveid = strings.TrimPrefix(lines[i], "Candidate")
			cveid = strings.TrimSpace(cveid)
			cve[cveid] = CveData{}
			continue
		}
		if strings.HasPrefix(lines[i], "Description:") { //got Description
			for i++; strings.HasPrefix(lines[i], " "); i++ { // so long as line begins with " "
				descr = descr + strings.TrimSpace(lines[i]) + " "
			}
			descr = strings.TrimSpace(descr)
			continue
		}
		if strings.HasPrefix(lines[i], "Priority:") { //got urgency
			urgency = strings.TrimPrefix(lines[i], "Priority:")
			urgency = strings.TrimSpace(urgency)
			continue
		}
		if strings.HasPrefix(lines[i], "Patches_") { //got package name
			pkg := strings.TrimPrefix(lines[i], "Patches_")
			pkg = strings.TrimSpace(strings.TrimSuffix(pkg, ":"))
			pkgs[pkg] = cve                                 //assign to package empty Response
			for i++; strings.Contains(lines[i], pkg); i++ { //search and fill releases for each package
				//get release name
				//ex: hardy_libxml2: not-affected (2.6.31.dfsg-2ubuntu1)
				// releaseName = hardy
				// status = not-affected
				// releaseVersion = 2.6.31.dfsg-2ubuntu1
				releaseInfo := strings.Split(lines[i], ":")
				if len(releaseInfo) < 2 {
					continue
				}
				releaseName := strings.TrimSuffix(releaseInfo[0], "_"+pkg)
				releaseInfo[1] = strings.TrimSpace(releaseInfo[1])
				status_version := strings.Split(releaseInfo[1], " ")
				status := strings.TrimSpace(status_version[0])
				releaseVersion := ""
				if len(status_version) > 1 {
					releaseVersion = strings.Trim((status_version[1]), "()")
				}
				releases[""]
			}
			continue
		}
	}
	return nil, nil
}
