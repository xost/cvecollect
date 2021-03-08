package main

import (
	"bytes"
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
		linkCh := make(chan string, 8)
		dataCh := make(chan []byte, 100)
		respCh := make(chan *uCve, 1000)
		var wgLink, wgData, wgResp sync.WaitGroup
		go func() {
			for d := range dataCh {
				wgData.Add(1)
				p.parseRaw(d, respCh)
				wgData.Done()
			}
		}()
		go func() {
			for r := range respCh {
				wgResp.Add(1)
				for k, v := range *r {
					resp[k] = v
				}
				wgResp.Done()
			}
		}()
		for i := 0; i < 8; i++ {
			go func() {
				for link := range linkCh {
					p.readUrl(link, dataCh)
					wgLink.Done()
				}
			}()
		}
		links = links[:111]
		rlog.Info("total links:", len(links))
		for i, link := range links {
			wgLink.Add(1)
			if i%100 == 0 {
				rlog.Info(i, "link is parsed")
			}
			linkCh <- p.url.Scheme + "://" + p.url.Host + link
		}
		wgLink.Wait()
		close(linkCh)
		wgData.Wait()
		close(dataCh)
		wgResp.Wait()
		close(respCh)
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
	req.Header.Set("User-Agent", "Golang_CVECollector_Bot/1.0")
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
		//rlog.Debug(resp.StatusCode)
	}
	dataCh <- data
}

func (u *ubuntu) parseRaw(raw []byte, respCh chan<- *uCve) {
	rdr := bytes.NewReader(raw)
	doc := html.NewTokenizer(rdr)
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tknType == html.TextToken {
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
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "Candidate:") && cveName == "" {
			//cveName = strings.TrimSpace(cveName)
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
			pkgs := map[string][]uRelease{pkgName: []uRelease{}}
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
	d := debian{name: "ubuntu"} //fake debian object
	return d.Query(cveId, pkgName, rdb)
}
