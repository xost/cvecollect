package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/romana/rlog"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type ubuntu struct {
	source string
	url    *url.URL
	dirs   []string
}

func NewUbuntu() (*ubuntu, error) {
	url, err := url.Parse(sources["ubuntu"])
	if err != nil {
		return nil, err
	}
	return &ubuntu{
		"",
		url,
		[]string{"/tree/active", "/tree/retired"},
	}, nil
}

func (p *ubuntu) CollectAll() Response { //todo: put out of ubuntu object
	resp := Response{}
	for _, dir := range p.dirs {
		rawdata, err := p.readUrl(p.url.String() + dir)
		if err != nil {
			rlog.Error(err)
			continue
		}
		links, err := p.listLinks(rawdata)
		if err != nil {
			rlog.Error(err)
			continue
		}
		for _, link := range links {
			rlog.Debug(link)
			rawdata, err = p.readUrl(p.url.Scheme + "://" + p.url.Host + link)
			if err != nil {
				rlog.Error(err)
				continue
			}
			resp1, err := p.parseRaw(rawdata)
			if err != nil {
				rlog.Error(err)
				continue
			}
			for k, v := range resp1 {
				resp[k] = v
			}
		}
	}
	return resp
}

func (p *ubuntu) Read(data *[]byte) (int, error) {
	c := http.Client{}
	req, err := http.NewRequest("GET", p.source, nil)
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

func (p *ubuntu) listLinks(raw []byte) ([]string, error) {
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
					tknType = doc.Next()
					if tknType == html.TextToken {
						tkn = doc.Token()
						if strings.HasPrefix(tkn.Data, "CVE-") {
							rslt = append(rslt, attr.Val)
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

func (u *ubuntu) parseRaw(raw []byte) (Response, error) {
	rdr := bytes.NewReader(raw)
	doc := html.NewTokenizer(rdr)
	var resp Response
	var err error
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tknType == html.TextToken {
			data := tkn.Data
			resp, err = u.parseText(string(data))
			if err != nil {
				return nil, err
			}
			if len(resp) > 0 {
				return resp, nil
			}
		}
	}
	return resp, nil
}

func (u *ubuntu) parseText(data string) (Response, error) {
	lines := strings.Split(data, "\n")
	pkgs := Response{}
	descr := ""
	urgency := ""
	cveid := ""
	fixedVersion := ""
	cve := make(map[string]CveData)
	//c := CveData1{
	//	Description: "de",
	//}
	//fmt.Println(c)
	releases := map[string]Release{}
	for i := 0; i < len(lines); i++ { //got cveid
		if strings.HasPrefix(lines[i], "Candidate:") { //maybe should add ' && cveid=="" '
			cveid = strings.TrimPrefix(lines[i], "Candidate:")
			cveid = strings.TrimSpace(cveid)
			cve[cveid] = CveData{
				"",
				make(map[string]Release),
				"",
			}
			continue
		}
		if strings.HasPrefix(lines[i], "Description:") { //got Description
			for i++; i < len(lines) && strings.HasPrefix(lines[i], " "); i++ { // so long as line begins with " "
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
		pkg := ""
		if strings.HasPrefix(lines[i], "Patches_") { //got package name
			pkg = strings.TrimPrefix(lines[i], "Patches_")
			pkg = strings.TrimSpace(strings.TrimSuffix(pkg, ":"))
			pkgs[pkg] = cve                                                   //assign to package empty Response
			for i++; i < len(lines) && strings.Contains(lines[i], pkg); i++ { //search and fill releases for each package
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
				releases[releaseName] = Release{
					fixedVersion,
					map[string]string{releaseName: releaseVersion},
					status,
					urgency,
				}
			}
			if pkg == "" || cveid == "" {
				continue
			}
			pkgs[pkg][cveid] = CveData{
				descr,
				releases,
				"local",
			}
		}
	}
	return pkgs, nil
}
