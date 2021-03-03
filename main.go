package main

import (
	"encoding/json"
	"fmt"
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
	addr = ""
	port = ""
	db   redis.Conn
	rh   *rejson.Handler
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
}

func main() {
	defer db.Close()
	http.Handle("/help", logWrapper(handleHelp))
	http.Handle("/update", logWrapper(handleUpdate))
	http.Handle("/cve/", logWrapper(handleGetCve))

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
	collectors := []Collector{
		NewDebian(),
		NewUbuntu(),
	}
	for _, c := range collectors {
		rlog.Info("Collecting CVE data for:", "\""+c.Name()+"\"")
		cve, err := c.Collect()
		if err != nil {
			rlog.Error(err)
			if len(*cve) == 0 {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Result is empty\n" + err.Error()))
				return
			}
		}
		res, err := rh.JSONSet(c.Name(), ".", *cve)
		if err != nil || res.(string) != "OK" {
			rlog.Error("Failed to update CVE data")
			rlog.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Failed to update CVE data"))
			return
		}
		rlog.Info("CVE data for", "\""+c.Name()+"\"", "was updated")
	}
	rlog.Info("CVE data was updated")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("CVE data was updated"))
}

func handleGetCve(w http.ResponseWriter, r *http.Request) { //todo cut and devide this func
	pathElements := strings.Split(r.URL.EscapedPath(), "/")
	if len(pathElements) != 3 {
		rlog.Error("Bad request")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad request"))
		return
	}
	cveid := "CVE-" + pathElements[len(pathElements)-1]
	src := r.URL.Query().Get("source")
	pkg := r.URL.Query().Get("pkg")
	rlog.Debug("source=", src, ", pkg=", pkg, ", cveid=", cveid)
	if src != "" && pkg != "" { //all params is present
		path := fmt.Sprintf(".%s[\"%s\"]", pkg, cveid)
		rlog.Debug("path=", path, "\n")
		raw, err := rh.JSONGet(src, path)
		if err != nil {
			rlog.Error(err)
			return
		}
		rawBytes, ok := raw.([]byte)
		if !ok {
			rlog.Error("Internal server error")
			rlog.Debug("Can't parse redis's response")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(rawBytes)
		return
	}
	if src != "" { //pkg is empty src and cveid is present
		rlog.Debug("path= .", "\n")
		raw, err := rh.JSONGet(src, ".")
		if err != nil {
			rlog.Error(err)
			return
		}
		rawBytes, ok := raw.([]byte)
		if !ok {
			rlog.Error("Internal server error")
			rlog.Debug("Can't parse redis's response")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}
		resp := Response{}
		err = json.Unmarshal(rawBytes, &resp)
		if err != nil {
			rlog.Error("Internal server error")
			rlog.Debug("Can't parse redis's response")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}
		resp1 := Response{}
		for k, v := range resp { //looking for particular cveid
			if cve, ok := v[cveid]; ok {
				rlog.Debug(k, cve)
				resp1[k] = map[string]CveData{cveid: cve}
			}
		}
		bytesResponse, err := json.Marshal(resp1)
		if err != nil {
			rlog.Error("Internal server error")
			rlog.Debug("Can't parse redis's response")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(bytesResponse)
		return
	}
}

func genPath(u *url.URL) (string, error) {
	return "", nil
}
