package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
)

var (
	jsonFileName  = "debTest.json"
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
)

func Deb(t *testing.T) {
	fh, err := os.Open(jsonFileName)
	if err != nil {
		t.Error(err)
	}
	defer fh.Close()
	raw, err := ioutil.ReadAll(fh)
	if err != nil {
		t.Error(err)
	}
	resp := new(Response)
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
	_, err := d.Read(&raw)
	if err != nil {
		t.Error(err)
	}
	resp := Response{}
	err = json.Unmarshal(raw, &resp)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(resp["fuse3"]["CVE-2018-10906"])
}

func RedisStore(t *testing.T) {
	d := NewDebian()
	raw := make([]byte, 0)
	_, err := d.Read(&raw)
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
	resp, err := u.Collect(rh)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(resp)
}

func TestUbuntuQuery(t *testing.T) {
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
	cveId := "2018-10906"
	j, err := c.Query(cveId, "fuse3", rh)
	_ = j
	if err != nil {
		t.Error(err)
		return
	}
	rlog.Debug(string(j))
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
	data, err := c.Collect(rh)
	if err != nil {
		t.Error(err)
	}
	cveData := data.(Cve)
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
