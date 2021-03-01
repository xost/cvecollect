package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/romana/rlog"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type ubuntu struct {
	source string
	name   string
	descr  string
	url    *url.URL
	dirs   []string
}

func NewUbuntu() *ubuntu {
	url, err := url.Parse(sources["ubuntu"])
	if err != nil {
		rlog.Error(err)
		return nil
	}
	return &ubuntu{
		"",
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

func (p *ubuntu) Collect() (resp *Response, err error) { //todo: put out of ubuntu object
	for _, dir := range p.dirs {
		dirCh := make(chan []byte, 1)
		p.readUrl(p.url.String()+dir, dirCh)
		links, err := p.listLinks(<-dirCh)
		if err != nil {
			rlog.Error(err)
			continue
		}
		linkCh := make(chan string, 500)
		dataCh := make(chan []byte, 500)
		respCh := make(chan Response, 500)
		var wgLink, wgRaw, wgResp sync.WaitGroup
		go func() {
			for d := range dataCh {
				wgRaw.Add(1)
				p.parseRaw(d, respCh)
				wgRaw.Done()
			}
		}()
		go func() {
			for r := range respCh {
				wgResp.Add(1)
				for k, v := range r {
					(*resp)[k] = v
				}
				wgResp.Done()
			}
		}()
		for i := 0; i < 500; i++ {
			go func() {
				for link := range linkCh {
					p.readUrl(link, dataCh)
					wgLink.Done()
				}
			}()
		}
		rlog.Debug("LAST LINK:", links[len(links)-1])
		for _, link := range links {
			wgLink.Add(1)
			linkCh <- p.url.Scheme + "://" + p.url.Host + link
		}
		wgLink.Wait()
		close(linkCh)
		wgRaw.Wait()
		close(dataCh)
		wgResp.Wait()
		close(respCh)
	}
	return
}

func (p *ubuntu) Read(data *[]byte) (n int, err error) {
	c := http.Client{}
	req, err := http.NewRequest("GET", p.source, nil)
	if err != nil {
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data1, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	*data = data1[:]
	n = len(*data)
	return
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

func (u *ubuntu) readUrl(url string, dataCh chan<- []byte) {
	c := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	dataCh <- data
}

func (u *ubuntu) parseRaw(raw []byte, respCh chan<- Response) {
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
				rlog.Error(err)
				continue
			}
			if len(resp) == 0 {
				rlog.Warn("Content is empty.")
			}
			respCh <- resp
		}
	}
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
