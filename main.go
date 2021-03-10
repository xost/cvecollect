package main

import (
	"net/http"
	"net/url"
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
	}
}

func main() {
	defer db.Close()
	http.Handle("/api/help", logWrapper(handleHelp))
	http.Handle("/api/update", logWrapper(handleUpdate))
	http.Handle("/api/cve/", logWrapper(handleGetCve))

	rlog.Info("Listen on " + addr + ":" + port)
	err := http.ListenAndServe(addr+":"+port, nil)
	if err != nil {
		rlog.Critical(err)
	}
}

func logWrapper(n http.HandlerFunc) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			rlog.Debug(
				"Method:", r.Method,
				"Path:", r.URL.EscapedPath(),
				"Query", r.URL.RawQuery,
			)
			n.ServeHTTP(w, r)
		},
	)
}

func handleHelp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("/api/update – обновляет базу, загружая всю необходимую информацию из источников\n"))
	w.Write([]byte("/api/cve/{CVE-ID}?source={SOURCE-NAME}&pkg={PKG-NAME}, т.е. указание ID CVE, источника ифнормации (Redhat, Ubuntu, NIST, Debian), и имени пакета\n"))
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	for _, c := range collectors {
		rlog.Info("Collecting CVE data for:", "\""+c.Name()+"\"")
		resp, err := c.Collect(rh)
		if err != nil {
			rlog.Error(err)
			continue
		}
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

func handleGetCve(w http.ResponseWriter, r *http.Request) { //todo cut and devide this func
	pathElements := strings.Split(r.URL.EscapedPath(), "/")
	if len(pathElements) != 4 {
		rlog.Error("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad request"))
		return
	}
	cveId := pathElements[len(pathElements)-1]
	src := r.URL.Query().Get("source")
	pkg := r.URL.Query().Get("pkg")
	rlog.Debug("cveId:", cveId, ", source:", src, ", pkg:", pkg)
	var source map[string]Collector
	if src != "" {
		source = map[string]Collector{src: collectors[src]}
	} else {
		source = collectors
	}
	json := make([]byte, 0)
	for name, c := range source {
		jsonRaw, err := c.Query(cveId, pkg, rh)
		if err != nil {
			rlog.Error(name, err)
			continue
		}
		json = append(json, jsonRaw...)
		rlog.Debug(jsonRaw)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func genPath(u *url.URL) (string, error) {
	return "", nil
}
