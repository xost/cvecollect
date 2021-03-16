package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
)

var (
	jsonDebFile = "debTest.json"

	ubuntuCveText = `Candidate: CVE-2018-10906
PublicDate: 2018-07-24 20:29:00 UTC
References:
 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10906
 https://github.com/libfuse/libfuse/pull/268
 https://sourceforge.net/p/fuse/mailman/message/36374753/
Description:
 In fuse before versions 2.9.8 and 3.x before 3.2.5, fusermount is
 vulnerable to a restriction bypass when SELinux is active. This allows
 non-root users to mount a FUSE file system with the 'allow_other' mount
 option regardless of whether 'user_allow_other' is set in the fuse
 configuration. An attacker may use this flaw to mount a FUSE file system,
 accessible by other users, and trick them into accessing files on that file
 system, possibly causing Denial of Service or other unspecified effects.
Ubuntu-Description:
Notes:
Bugs:
 http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=904216
 http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=904439
Priority: low
Discovered-by:
Assigned-to:
CVSS:
 nvd: CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H


Patches_fuse3:
upstream_fuse3: needs-triage
precise/esm_fuse3: DNE
trusty_fuse3: DNE
trusty/esm_fuse3: DNE
xenial_fuse3: DNE
bionic_fuse3: DNE
cosmic_fuse3: DNE
disco_fuse3: ignored (reached end-of-life)
eoan_fuse3: ignored (reached end-of-life)
focal_fuse3: needs-triage
groovy_fuse3: needs-triage
devel_fuse3: needs-triage

Patches_fuse:
upstream_fuse: needs-triage
precise/esm_fuse: needs-triage
trusty_fuse: ignored (reached end-of-life)
trusty/esm_fuse: needs-triage
xenial_fuse: needs-triage
bionic_fuse: needs-triage
cosmic_fuse: ignored (reached end-of-life)
disco_fuse: ignored (reached end-of-life)
eoan_fuse: ignored (reached end-of-life)
focal_fuse: needs-triage
groovy_fuse: needs-triage
devel_fuse: needs-triage`

	redhatJsonFile = "redhatTest.json"
)

type test struct {
	cveID   string
	pkg     string
	source  string
	control string
}

var testsDebian map[string]test = map[string]test{
	"cveID": test{
		"2012-0833",
		"",
		"debian",
		`{"389-ds-base":{"description":"The acllas__handle_group_entry function in servers\/plugins\/acl\/acllas.c in 389 Directory Server before 1.2.10 does not properly handled access control instructions (ACIs) that use certificate groups, which allows remote authenticated LDAP users with a certificate group to cause a denial of service (infinite loop and CPU consumption) by binding to the server.","releases":{"bullseye":{"fixed_version":"0","repositories":{"bullseye":"1.4.4.11-1"},"status":"resolved","urgency":"unimportant"},"buster":{"fixed_version":"0","repositories":{"buster":"1.4.0.21-1"},"status":"resolved","urgency":"unimportant"},"sid":{"fixed_version":"0","repositories":{"sid":"1.4.4.11-1"},"status":"resolved","urgency":"unimportant"},"stretch":{"fixed_version":"0","repositories":{"stretch":"1.3.5.17-2"},"status":"resolved","urgency":"unimportant"}},"scope":"local"}}`,
	},
}

func Deb(t *testing.T) {
	fh, err := os.Open(jsonDebFile)
	if err != nil {
		t.Error(err)
	}
	defer fh.Close()
	raw, err := ioutil.ReadAll(fh)
	if err != nil {
		t.Error(err)
	}
	resp := new(debResponse)
	err = json.Unmarshal(raw, &resp)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(resp)
}

func DebRequest(t *testing.T) {
	d := debian{}
	d.setURL(sources["debian"])
	raw := make([]byte, 0)
	_, err := d.read(&raw)
	if err != nil {
		t.Error(err)
	}
	resp := debResponse{}
	err = json.Unmarshal(raw, &resp)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(resp["fuse3"]["CVE-2018-10906"])
}

func RedisStore(t *testing.T) {
	d := NewDebian()
	raw := make([]byte, 0)
	_, err := d.read(&raw)
	if err != nil {
		t.Error(err)
	}
	resp, err := d.parse(raw)
	if err != nil {
		t.Error(err)
	}
	c, err := redis.Dial("tcp", "localhost:6379")
	if err != nil {
		t.Error(err)
	}
	rh := rejson.NewReJSONHandler()
	rh.SetRedigoClient(c)
	_, err = rh.JSONSet("debian", ".", resp)
	if err != nil {
		t.Error(err)
	}
	//_ = c
	//for k, v := range resp {

	//	fmt.Println(k)
	//	for kk, _ := range v {
	//		fmt.Println("\t", kk)
	//	}
	//}
}

func UbuntuCollectAll(t *testing.T) {
	rlog.Debug("Go test ubuntu CollectAll")
	u := NewUbuntu()
	resp, err := u.Collect()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(resp)
}

func UbuntuQuery(t *testing.T) {
	c := NewUbuntu()
	//data, err := c.Collect(rh)
	//if err != nil {
	//	t.Error(err)
	//	return
	//}
	//res, err := rh.JSONSet(c.Name(), ".", data)
	//if err != nil || res.(string) != "OK" {
	//	rlog.Error("Failed to update CVE data")
	//	rlog.Error(err)
	//	return
	//}
	cveID := "2018-10906"
	j, err := c.Query(cveID, "", rh)
	_ = j
	if err != nil {
		t.Error(err)
		return
	}
	rlog.Debug(string(j))
}

func Query(t *testing.T) {
	url := "https://127.0.0.1:3000/api/cve/2018-10906?source=ubuntu&pkg=fuse"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Error(err)
		return
	}
	c := http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	defer resp.Body.Close()
	bts, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}
	rlog.Println(string(bts))
}

func HandleUpdate(t *testing.T) {
	c := http.Client{}
	req, err := http.NewRequest("GET", "http://127.0.0.1:3000/update", nil)
	if err != nil {
		t.Error(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
}

func DebianCollect(t *testing.T) {
	c := NewDebian()
	data, err := c.Collect()
	if err != nil {
		t.Error(err)
	}
	cveData := data.(debCve)
	rlog.Debug(cveData["CVE-2018-10906"])
}

func DebianQuery(t *testing.T) {
	c := NewDebian()
	//data, err := c.Collect(rh)
	//if err != nil {
	//	t.Error(err)
	//}
	//res, err := rh.JSONSet(c.Name(), ".", data)
	//if err != nil || res.(string) != "OK" {
	//	rlog.Error("Failed to update CVE data")
	//	rlog.Error(err)
	//}
	j, err := c.Query("2018-10906", "fuse3", rh)
	if err != nil {
		t.Error(err)
	}
	rlog.Debug(string(j))

}

func RedhatQeury(t *testing.T) {
	rh := NewRedhat()
	data := rhCve{}
	pkg := "fuse"
	r, err := rh.Query("2018-10906", pkg, nil)
	if err != nil {
		t.Error(err)
		return
	}
	//fmt.Printf("%p\n", &data.Packages)
	//rlog.Println(string(r))
	err = json.Unmarshal(r, &data)
	for _, p := range data.Packages {
		rlog.Println(p.Name)
	}
}

func NistCollect(t *testing.T) {
	c := NewNist()
	data, err := c.Collect()
	if err != nil {
		t.Error(err)
		return
	}
	_ = data
	//rlog.Debug(data)
}

func NistQuery(t *testing.T) {
	n := NewNist()
	cveID := "cpe:2.3:a:10web:form_maker:*:*:*:*:*:wordpress:*:*"
	//cveID := "cpe:2.3:o:zyxel:zld:*:*:*:*:*:*:*:*"
	data, err := n.Query(cveID, "", rh)
	if err != nil {
		t.Error(err)
		return
	}
	rlog.Debug(string(data))
}

func TestDebCollect(t *testing.T) {
	d := NewDebian()
	data, err := d.Collect()
	if err != nil {
		t.Error(err)
		return
	}
	_ = data
	//debData, ok := data.(debCve)
	//if !ok {
	//	t.Error("Can't cast result to debCve type")
	//	return
	//}
	//if len(debData) == 0 {
	//	t.Error("Result is empty")
	//	return
	//}
}

func TestDebCollectWrongURL(t *testing.T) {
	d := NewDebian()
	d.setURL("broken link")
	data, err := d.Collect()
	if err == nil {
		t.Error(err)
		return
	}
	_ = data
}

//it takes about 2 hours
//func TestUbuntuCollect(t *testing.T) {
//	u := NewUbuntu()
//	data, err := u.Collect()
//	if err != nil {
//		t.Error(err)
//		return
//	}
//}

func TestRHCollect(t *testing.T) {
	r := NewRedhat()
	data, err := r.Collect()
	if err != nil {
		t.Error(err)
		return
	}
	_ = data
}
func TestNistCollect(t *testing.T) {
	n := NewNist()
	data, err := n.Collect()
	if err != nil {
		t.Error(err)
		return
	}
	_ = data
}

func TestDebCveRequest(t *testing.T) {
	cveID := "2018-0833"
	source := "debian"
	srv := httptest.NewServer(handlers())
	defer srv.Close()

	resp, err := http.Get(fmt.Sprintf("http://%s:%s/api/cve/CVE-%s?source=%s", addr, port, cveID, source))
	if err != nil {
		t.Error(err)
		return
	}
	defer resp.Body.Close()
}
