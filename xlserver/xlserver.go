package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

////////////////////////////////////////////////////////////////////////////////

type settings struct {
	bindIp   string
	certFile string
	keyFile  string
}

func getCommandLineSettings() settings {
	ret := settings{}

	flag.StringVar(&ret.bindIp,
		"bindIp",
		"0.0.0.0",
		"Server bind IP")
	flag.StringVar(&ret.certFile,
		"certFile",
		"xlserver.crt",
		"Path to Certificate Authority (CA) file")
	flag.StringVar(&ret.keyFile,
		"keyFile",
		"xlserver.key",
		"Path to private key file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	return ret
}

////////////////////////////////////////////////////////////////////////////////

func checkHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("You are good to go.\n"))
}

func main() {
	sts := getCommandLineSettings()
	http.HandleFunc("/check", checkHandler)
	err := http.ListenAndServeTLS(sts.bindIp+":443", sts.certFile, sts.keyFile, nil)
	if err != nil {
		log.Fatal("Failed to start the server. ", err)
	}
}
