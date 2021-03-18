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

func (u *ubuntu) Name() string {
	return u.name
}

func (u *ubuntu) Descr() string {
	return u.descr
}

func (u *ubuntu) Collect() (interface{}, error) { //todo: put out of ubuntu object
	resp := uCve{}
	//there is different dirs to parse active and retired
	for _, dir := range u.dirs {
		dirCh := make(chan []byte, 1)
		u.readUrl(u.url.String()+dir, dirCh)
		//getting all links in custom directory
		links, err := u.listLinks(<-dirCh)
		if err != nil {
			rlog.Error(err)
			continue
		}
		linkCh := make(chan string, 10)
		dataCh := make(chan []byte, 200)
		respCh := make(chan *uCve, 100)
		var wgr sync.WaitGroup
		//parse content and search data in <code></code> tags
		go func() {
			for d := range dataCh {
				wgr.Add(1)
				go func(dd []byte) {
					u.parseRaw(dd, respCh)
					wgr.Done()
				}(d)
			}
			wgr.Wait()
			close(respCh)
		}()

		//go on link and get all content
		go func() {
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					for link := range linkCh {
						u.readUrl(link, dataCh)
					}
					wg.Done()
				}()
			}
			wg.Wait()
			close(dataCh)
		}()
		//it produces 503 error. maybe because of ddos protection
		//go func() {
		//	var wg sync.WaitGroup
		//	for link := range linkCh {
		//		wg.Add(1)
		//		go func(l string, w *sync.WaitGroup) {
		//			u.readUrl(l, dataCh)
		//			wg.Done()
		//		}(link, &wg)
		//	}
		//	wg.Wait()
		//	close(dataCh)
		//}()

		//links = links[8000 : len(links)-1] //plug
		rlog.Info("total links:", len(links))
		//pass through all links
		for i, link := range links {
			linkCh <- u.url.Scheme + "://" + u.url.Host + link
			if i%1000 == 0 {
				rlog.Info(i, "link is parsed")
			}
		}
		//close channel for quit all goroutines
		close(linkCh)

		//collect ann data from response channel
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

func (u *ubuntu) listLinks(raw []byte) ([]string, error) {
	rdr := bytes.NewReader(raw)
	doc := html.NewTokenizer(rdr)
	rslt := make([]string, 0)
	//pass through tags while tknType != html.ErrorToken (no more tags)
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tknType == html.StartTagToken { //openned tag like <a...>
			if tkn.DataAtom != atom.A { // <a...> tag
				continue
			}
			for _, attr := range tkn.Attr { //list all attrs
				if attr.Key == "href" { //get href attr
					tknType = doc.Next()
					if tknType == html.TextToken {
						tkn = doc.Token()
						if strings.HasPrefix(tkn.Data, "CVE-") { //if it is CVE link then get the link
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
	resp, err := http.Get(url)
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
	//if StatusCode is not OK, skip this content
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
	//pass throught all tags
	for tknType := doc.Next(); tknType != html.ErrorToken; tknType = doc.Next() {
		tkn := doc.Token()
		if tkn.Data == "code" && tknType == html.StartTagToken { // search openned <code> tag
			doc.Next()
			tkn = doc.Token()
			data := tkn.Data
			resp := u.parseText([]byte(data)) //and parse <code> data </code>
			// if resp is empty, skip it
			if resp == nil {
				continue
			}
			respCh <- resp
		}
	}
}

func (u *ubuntu) parseText(data []byte) *uCve {
	lines := strings.Split(string(data), "\n")
	var cve uCve // nil
	cveData := uCveData{}
	cveName := ""
	pkgs := make(map[string][]uRelease)
	for i := 0; i < len(lines); i++ {
		//if line begins with Candidate then end with CVE-XXX-XXXX
		if strings.HasPrefix(lines[i], "Candidate:") && cveName == "" {
			cveName, i = tabbedLines(lines, "Candidate:", i)
			continue
		}
		//and so on...
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
		//if line like Patches_fuse3 then fuse3 is package name. take it
		if strings.HasPrefix(lines[i], "Patches_") { //got package name
			pkgName := strings.TrimPrefix(lines[i], "Patches_")
			pkgName = strings.Trim(pkgName, ": ")
			pkgs[pkgName] = make([]uRelease, 0)                                   //make empty pkg map
			for i++; i < len(lines) && strings.Contains(lines[i], pkgName); i++ { //while line contains package, take line
				nameStatus := strings.Split(lines[i], ":")
				if len(nameStatus) < 2 {
					continue
				}
				release := uRelease{}
				release.Name = strings.TrimSuffix(nameStatus[0], "_"+pkgName) //xxxx_pkgName. xxxx - release name
				release.Status = strings.TrimSpace(nameStatus[1])             //after ":" follows pkg status for this release
				pkgs[pkgName] = append(pkgs[pkgName], release)
			}
			cveData.Packages = pkgs
		}
		//if didn't fine Cve name, skip it
		if cveName != "" {
			cve = uCve{cveName: cveData}
		}
	}
	return &cve
}

func (u *ubuntu) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	cveName := "CVE-" + cveId
	path := fmt.Sprintf("[\"%s\"]", cveName)

	cveData, err := rdb.JSONGet(u.Name(), path)
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
