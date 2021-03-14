package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type ubuntu struct {
	name  string
	descr string
	url   *url.URL
	dirs  []string
}

type uCveData struct {
	Description       string    `json:"description,omitempty"`
	PublicDate        string    `json:"public_date,omitempty"`
	References        string    `json:"references,omitempty"`
	UbuntuDescription string    `json:"ubuntu_description,omitempty"`
	Notes             string    `json:"notes,omitempty"`
	Mitigation        string    `json:"mitigation,omitempty"`
	Bugs              string    `json:"bugs,omitempty"`
	Priority          string    `json:"priority,omitempty"`
	Discovered        string    `json:"descovered,omitempty"`
	Assigned          string    `json:"assigned,omitempty"`
	Cvss              string    `json:"cvss,omitempty"`
	Packages          uPackages `json:"packages,omitempty"`
}

type uPackages map[string][]uRelease

type uRelease struct {
	Name   string `json:"release"`
	Status string `json:"status,omitempty"`
}

type uCve map[string]uCveData

func NewUbuntu() *ubuntu {
	url, err := url.Parse(sources["ubuntu"])
	if err != nil {
		rlog.Error(err)
		return nil
	}
	return &ubuntu{
		//		"",
		"ubuntu",
		"Ubuntu CVE data.",
		url,
		//[]string{"/tree/active"},
		[]string{"/tree/active", "/tree/retired"},
	}
}

func (p *ubuntu) Name() string {
	return p.name
}

func (p *ubuntu) Descr() string {
	return p.descr
}

func (p *ubuntu) Collect(rdb *rejson.Handler) (interface{}, error) { //todo: put out of ubuntu object
	resp := uCve{}
	for _, dir := range p.dirs {
		dirCh := make(chan []byte, 1)
		p.readUrl(p.url.String()+dir, dirCh)
		links, err := p.listLinks(<-dirCh)
		if err != nil {
			rlog.Error(err)
			continue
		}
		linkCh := make(chan string, 10)
		dataCh := make(chan []byte, 200)
		respCh := make(chan *uCve, 100)
		var wgr sync.WaitGroup
		go func() {
			for d := range dataCh {
				wgr.Add(1)
				go func(dd []byte) {
					p.parseRaw(dd, respCh)
					wgr.Done()
				}(d)
			}
			wgr.Wait()
			close(respCh)
		}()

		go func() {
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					for link := range linkCh {
						p.readUrl(link, dataCh)
					}
					wg.Done()
				}()
			}
			wg.Wait()
			close(dataCh)
		}()
		//it produces 503 error. maybe because ddos protection
		//go func() {
		//	var wg sync.WaitGroup
		//	for link := range linkCh {
		//		wg.Add(1)
		//		go func(l string, w *sync.WaitGroup) {
		//			p.readUrl(l, dataCh)
		//			wg.Done()
		//		}(link, &wg)
		//	}
		//	wg.Wait()
		//	close(dataCh)
		//}()

		//links = links[8000 : len(links)-1] //plug
		rlog.Info("total links:", len(links))
		for i, link := range links {
			linkCh <- p.url.Scheme + "://" + p.url.Host + link
			if i%100 == 0 {
				rlog.Info(i, "link is parsed")
			}
		}
		close(linkCh)

		for r := range respCh {
			for k, v := range *r {
				if _, ok := resp[k]; ok {
					rlog.Debug("key:", k, "is exists")
				}
				resp[k] = v
			}
		}
	}
	return resp, nil
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

func (u *ubuntu) readUrl(url string, dataCh chan<- []byte) {
	c := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	//req.Header.Set("User-Agent", "Golang_CVECollector_Bot/1.0")
	resp, err := c.Do(req)
	if err != nil {
		rlog.Error(err)
		return
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		rlog.Error(err)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		rlog.Error(url, "http status code:", resp.StatusCode)
		return
	} else {
	}
	dataCh <- data
}

func (u *ubuntu) parseRaw(raw []byte, respCh chan<- *uCve) {
	rdr := bytes.NewReader(raw)
	doc := html.NewTokenizer(rdr)
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tkn.Data == "code" && tknType == html.StartTagToken {
			doc.Next()
			tkn = doc.Token()
			data := tkn.Data
			resp := u.parseText([]byte(data))
			if resp == nil {
				continue
			}
			respCh <- resp
		}
	}
}

func (p *ubuntu) parseText(data []byte) *uCve {
	lines := strings.Split(string(data), "\n")
	var cve uCve // nil
	cveData := uCveData{}
	cveName := ""
	pkgs := make(map[string][]uRelease)
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "Candidate:") && cveName == "" {
			cveName, i = tabbedLines(lines, "Candidate:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "PublicDate:") {
			cveData.PublicDate, i = tabbedLines(lines, "PublicDate:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "References:") {
			cveData.References, i = tabbedLines(lines, "References:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Description:") {
			cveData.Description, i = tabbedLines(lines, "Description:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Ubuntu-Description:") {
			cveData.UbuntuDescription, i = tabbedLines(lines, "Ubuntu-Description:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Notes:") {
			cveData.Notes, i = tabbedLines(lines, "Notes:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Mitigation:") {
			cveData.Mitigation, i = tabbedLines(lines, "Mitigation:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Priority:") {
			cveData.Priority, i = tabbedLines(lines, "Priority:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Discovered-by:") {
			cveData.Discovered, i = tabbedLines(lines, "Discovered-by:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Assigned-to:") {
			cveData.Assigned, i = tabbedLines(lines, "Assigned-to:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "CVSS:") {
			cveData.Cvss, i = tabbedLines(lines, "CVSS:", i)
			continue
		}
		if strings.HasPrefix(lines[i], "Patches_") { //got package name
			pkgName := strings.TrimPrefix(lines[i], "Patches_")
			pkgName = strings.Trim(pkgName, ": ")
			pkgs[pkgName] = make([]uRelease, 0)
			for i++; i < len(lines) && strings.Contains(lines[i], pkgName); i++ { //all about release
				nameStatus := strings.Split(lines[i], ":")
				if len(nameStatus) < 2 {
					continue
				}
				release := uRelease{}
				release.Name = strings.TrimSuffix(nameStatus[0], "_"+pkgName)
				release.Status = strings.TrimSpace(nameStatus[1])
				pkgs[pkgName] = append(pkgs[pkgName], release)
			}
			cveData.Packages = pkgs
		}
		if cveName != "" {
			cve = uCve{cveName: cveData}
		}
	}
	return &cve
}

func (p *ubuntu) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	// the same as debian.Query
	//d := debian{name: "ubuntu"} //fake debian object
	//return d.Query(cveId, pkgName, rdb)

	cveName := "CVE-" + cveId
	path := fmt.Sprintf("[\"%s\"]", cveName)

	cveData, err := rdb.JSONGet(p.Name(), path)
	if err != nil {
		return nil, err
	}
	cveBytes, ok := cveData.([]byte)
	if !ok {
		return nil, errors.New("Can't case ....: ")
	}
	if pkgName != "" {
		c := uCveData{}
		err := json.Unmarshal(cveBytes, &c)
		if err != nil {
			return nil, err
		}
		for name, _ := range c.Packages {
			rlog.Debug(name)
			if name != pkgName {
				delete(c.Packages, name)
			}
		}
		if len(c.Packages) < 1 {
			return nil, errors.New("requested package does not found")
		}
		cveBytes, err = json.Marshal(&c)
		if err != nil {
			return nil, err
		}
	}
	return cveBytes, nil

}
