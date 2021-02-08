package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	debianSource = "https://security-tracker.debian.org/tracker/data/json"
	logFile      = "info.log"
)

var (
	loglevel = "INFO"
	addr     = "127.0.0.1"
	port     = "8080"
	dl       *log.Logger
	el       *log.Logger
	il       *log.Logger
)

func init() {
	// env config
	// LOGLEVEL = {INFO,ERROR,DEBUG}
	// ADDR
	// PORT
	_loglevel := os.Getenv("LOGLEVEL")
	switch _loglevel {
	case "INFO", "WARN", "ERROR", "DEBUG":
		loglevel = _loglevel
	case "":
	default:
		log.Println("Wrong LOGLEVEL")
	}
	_addr := os.Getenv("ADDR")
	if _addr != "" {
		addr = _addr
	}
	_port := os.Getenv("PORT")
	if _port != "" {
		port = _port
	}
}

func main() {
	//lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 644)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer lf.Close()
	switch loglevel {
	case "INFO":
		dl = log.New(ioutil.Discard, "", 0)
		el = log.New(ioutil.Discard, "", 0)
		il = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	case "ERROR":
		dl = log.New(ioutil.Discard, "", 0)
		el = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
		il = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	case "DEBUG":
		dl = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
		el = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
		il = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	}

	http.HandleFunc("/hello", handleHello)

	http.ListenAndServe(":8080", nil)
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("HELLO\n"))
}
