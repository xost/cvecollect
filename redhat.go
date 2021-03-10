package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nitishm/go-rejson"
)

type redhat struct {
	url   string
	name  string
	descr string
}

type rhCve struct {
	Severity string      `json:"threat_severity,omitempty"`
	Date     string      `json:"public_date,omitempty"`
	Bugz     bugzilla    `json:"bugzilla,omitempty"`
	Cvss     cvss3       `json:"cvss3,omitempty"`
	Cwe      string      `json:"cwe,omitempty"`
	Details  []string    `json:"details,omitempty"`
	Packages []rhpackage `json:"package_state,omitempty"`
	Releases []rhrelease `json:"affected_releases,omitempty"`
	Acknow   string      `json:"acknowledgement,omitempty"`
	Csaw     bool        `json:"csaw,omitempty"`
}

type cvss3 struct {
	BaseScore     string `json:"cvss3_base_score,omitempty"`
	ScoringVector string `json:"cvss3_scoring_vector,omitempty"`
	Status        string `json:"status,omitempty"`
}

type bugzilla struct {
	Description string `json:"description,omitempty"`
	Id          string `json:"id,omitempty"`
	Url         string `json:"url,omitempty"`
}

type rhrelease struct {
	Name    string `json:"product_name,omitempty"`
	Date    string `json:"release_date,omitempty"`
	Adv     string `json:"advisory,omitempty"`
	Cpe     string `json:"cpe,omitempty"`
	Package string `json:"package,omitempty"`
}

type rhpackage struct {
	Name    string `json:"package_name,omitempty"`
	Product string `json:"product_name,omitempty"`
	State   string `json:"fix_state,omitempty"`
	Cpe     string `json:"cpe,omitempty"`
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

func (p *redhat) Descr() string {
	return p.descr
}

func (p *redhat) Collect(rdb *rejson.Handler) (interface{}, error) {
	//redhat.Collect does not collect any data
	return nil, nil
}

func (p *redhat) Query(cveId, pkgName string, rdb *rejson.Handler) ([]byte, error) {
	cveName := "CVE-" + cveId
	c := http.Client{}
	url := fmt.Sprintf("%s/%s.json", p.url, cveName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data := rhCve{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	//cut mismatched packages
	if pkgName != "" {
		p := data.Packages
		for i := 0; i < len(p); i++ {
			if p[i].Name != pkgName {
				p = append(p[:i], p[i+1:]...)
				i--
			}
		}
		data.Packages = p
	}
	j, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return j, nil
}
