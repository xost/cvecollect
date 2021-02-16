package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/nitishm/go-rejson"
)

var (
	jsonFileName = "debTest.json"
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
	resp := new(response)
	err = json.Unmarshal(raw, &resp)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(resp)
}

func DebRequest(t *testing.T) {
	d := debian{}
	d.SetURL(sources["debian"])
	raw := make([]byte, 0)
	_, err := d.Read(&raw)
	if err != nil {
		t.Error(err)
	}
	resp := response{}
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
	resp, err := d.Parse(raw)
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

func TestUbuntuListTokens(t *testing.T) {
	u := NewUbuntu()
	raw := make([]byte, 0)
	_, err := u.Read(&raw)
	if err != nil {
		t.Error(err)
	}
	nds, _ := u.listNodes(raw)
	fmt.Println(nds)
}
