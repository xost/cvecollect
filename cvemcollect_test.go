package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var (
	jsonFileName = "debTest.json"
)

func TestDeb(t *testing.T) {
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

func TestDebRequest(t *testing.T) {
	d := debian{}
	d.SetURL(debianSource)
	raw := make([]byte, 0)
	_, err := d.Read(&raw)
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
