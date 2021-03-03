package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
)

type redhat struct {
	url   string
	name  string
	descr string
}

type redhatCve struct {
	Cveid    string          `json:"name"`
	Bugzilla redhatBugzilla  `json:"bugzilla"`
	Details  []string        `json:"details"`
	Releases []redhatRelease `json:"affected_release"`
	Packages []redhatPackage `json:"package_state"`
	Urgency  string          `json:"threat_severity"`
}

type redhatBugzilla struct {
	Description string `json:"description"`
}

type redhatRelease struct {
	Product string `json:"product_name"`
	Package string `json:"package"`
}

type redhatPackage struct {
	Name    string `json:"package_name"`
	Product string `json:"product_name"`
	Status  string `json:"fix_state"`
}

func NewRedhat() *redhat {
	return &redhat{
		sources["redhat"],
		"redhat",
		"Redhat CVE data.",
	}
}

func (p *redhat) Name() string {
	return p.name
}

func (p *redhat) Description() string {
	return p.descr
}

func (p *redhat) Collect() (*Response, error) {
	return nil, errors.New("redhat.Collect does not collect any data")
}

func (p *redhat) Get(cveid, pkg string, rdb *rejson.Handler) (r *Response, err error) {
	cveName := "CVE-" + cveid
	c := http.Client{}
	url := fmt.Sprintf("%s/%s.json", p.url, cveName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	rhcve := redhatCve{}
	err = json.NewDecoder(resp.Body).Decode(&rhcve)
	if err != nil {
		return
	}
	r1 := Response{}
	rlog.Info("***PACKAGES")
	for _, pkg := range rhcve.Packages {
		rlog.Println(pkg.Name, pkg.Product)
		//cve := CveData{}
		//cve.Description = rhcve.Bugzilla.Description
		//for _, rls := range rhcve.Releases {
		//	cve.Releases[rls.Product] = Release{}
		//}
		//r1[pkg.Name] = map[string]CveData{cveName: CveData{}}
	}
	rlog.Info("***RELEASES")
	r = &r1
	return
}

func (p *redhat) parse(data []byte) {
}
