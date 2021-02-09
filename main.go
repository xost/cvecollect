package main

import (
	"net/http"
	"os"

	"github.com/romana/rlog"
)

const (
	debianSource = "https://security-tracker.debian.org/tracker/data/json"
	logFile      = "info.log"
)

var (
	loglevel = "INFO"
	addr     = ""
	port     = ""
)

func init() {
	// init config
	// ADDR
	// PORT
	addr = os.Getenv("ADDR")
	if addr == "" {
		rlog.Warn("ADDR env is not set. Use default address 0.0.0.0.")
		addr = "0.0.0.0"
	}
	port = os.Getenv("PORT")
	if port == "" {
		rlog.Critical("PORT must be set.")
	}
}

func main() {
	http.Handle("/help", logWrapper(handleHelp))
	http.Handle("/update", logWrapper(handleUpdate))

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
	//only debian at now
	deb := NewDebian()
	data := make([]byte, 0)
	_, err := deb.Read(&data)
	if err != nil {
		rlog.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	debCve, err := deb.Parse(data)
	if err != nil {
		rlog.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = debCve
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
