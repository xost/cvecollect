package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/gomodule/redigo/redis"
	"github.com/nitishm/go-rejson"
	"github.com/romana/rlog"
)

var (
	sources = map[string]string{
		"debian": "https://security-tracker.debian.org/tracker/data/json",
		"ubuntu": "https://git.launchpad.net/ubuntu-cve-tracker",
		"redhat": "https://access.redhat.com/labs/securitydataapi/cve",
		"nist":   "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz",
	}
	addr       = ""
	port       = ""
	db         redis.Conn
	rh         *rejson.Handler
	collectors map[string]Collector
)

func init() {
	// init config
	addr = os.Getenv("ADDR")
	if addr == "" {
		rlog.Warn("ADDR env is not set. Use default address 0.0.0.0.")
		addr = "0.0.0.0"
	}
	port = os.Getenv("PORT")
	if port == "" {
		rlog.Critical("PORT must be set.")
		os.Exit(1)
	}
	dbPort := os.Getenv("DBPORT")
	if dbPort == "" {
		rlog.Warn("DBPORT env is not set. Use default redis port 6379.")
		dbPort = "6379"
	}
	dbHost := os.Getenv("DBHOST")
	if dbHost == "" {
		rlog.Warn("DBHOST env is not set. Use 127.0.0.1.")
		dbHost = "127.0.0.1"
	}
	var err error
	db, err = redis.Dial("tcp", dbHost+":"+dbPort)
	if err != nil {
		rlog.Critical(err)
		os.Exit(1)
	}
	rh = rejson.NewReJSONHandler()
	rh.SetRedigoClient(db)

	collectors = map[string]Collector{
		"debian": NewDebian(),
		"ubuntu": NewUbuntu(),
		"redhat": NewRedhat(),
		"nist":   NewNist(),
	}
}

func main() {
	defer db.Close()

	rlog.Info("Listen on " + addr + ":" + port)
	err := http.ListenAndServe(addr+":"+port, handlers())
	if err != nil {
		rlog.Critical(err)
	}
}

func logWrapper(n http.HandlerFunc) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			rlog.Debug(
				"Method:", r.Method,
				" Path:", r.URL.EscapedPath(),
				" Query:", r.URL.RawQuery,
			)
			n.ServeHTTP(w, r)
		},
	)
}

func handlers() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/update/", logWrapper(handleUpdate))
	mux.Handle("/api/cve/", logWrapper(handleGetCve))
	return mux
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	for _, c := range collectors {
		rlog.Info("Collecting CVE data for:", "\""+c.Name()+"\"")
		resp, err := c.Collect()
		if err != nil {
			rlog.Error(err)
			continue
		}
		//store data to redis database. source name is zero level key
		res, err := rh.JSONSet(c.Name(), ".", resp)
		if err != nil || res.(string) != "OK" {
			rlog.Error("Failed to update CVE data")
			rlog.Error(err)
			continue
		}
		rlog.Info("CVE data for", "\""+c.Name()+"\"", "was updated")
	}
	rlog.Info("CVE data was updated")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("CVE data was updated"))
}

func handleGetCve(w http.ResponseWriter, r *http.Request) {
	//get path's elements
	path := r.URL.EscapedPath()
	path = strings.Trim(path, "/")
	pathElements := strings.Split(path, "/")
	if len(pathElements) != 4 {
		rlog.Error("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad request"))
		return
	}
	//the last path's element is cveID
	cveID := pathElements[len(pathElements)-1]
	//get source
	src := r.URL.Query().Get("source")
	//get package name
	pkg := r.URL.Query().Get("pkg")
	rlog.Debug("cveID:", cveID, ", source:", src, ", pkg:", pkg)
	var sources map[string]Collector
	if src != "" { //if source not empty.
		sources = map[string]Collector{src: collectors[src]}
	} else { //scan all sources
		sources = collectors
	}
	json := make([]byte, 0)
	//searching...
	for name, c := range sources {
		jsonRaw, err := c.Query(cveID, pkg, rh)
		if err != nil {
			rlog.Error(name, err)
			continue
		}
		json = append(json, jsonRaw...)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}
