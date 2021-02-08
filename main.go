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
	addr     = ""
	port     = ""
	dl       *log.Logger
	el       *log.Logger
	il       *log.Logger
)

func init() {
	// env config
	// LOGLEVEL = {INFO,ERROR,DEBUG}
	// ADDR
	// PORT
	loglevel = os.Getenv("LOGLEVEL")
	switch loglevel {
	case "INFO", "WARN", "ERROR", "DEBUG":
	case "":
		loglevel = "INFO"
	default:
		log.Println("Wrong LOGLEVEL")
	}
	addr = os.Getenv("ADDR")
	if addr == "" {
		addr = "0.0.0.0"
	}
	port = os.Getenv("PORT")
	log.Println(port)
	if port == "" {
		log.Fatal("PORT must be set")
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

	log.Println(addr + ":" + port)
	err := http.ListenAndServe(addr+":"+port, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("HELLO\n"))
}
