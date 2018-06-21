package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
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

func getFileChecksum(fileName string) (string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeResponse(w http.ResponseWriter, resp string) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(resp))
}

func checkHandler(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	app := q["app"]
	ver := q["ver"]
	csum := q["csum"]

	if app == nil || ver == nil || csum == nil {
		writeResponse(w, "Not good")
		return
	}

	calc_csum, err := getFileChecksum(ver + ".server.class")
	if err != nil {
		writeResponse(w, "Not good")
		return
	} else if calc_csum != csum {
		writeResponse(w, "Not good")
		return
	}

	writeResponse(w, "XGFqCq6xm0gtFlbLDM0wRa1dm3FShwBerKhvebzA6So")
}

func main() {
	sts := getCommandLineSettings()
	http.HandleFunc("/check", checkHandler)
	err := http.ListenAndServeTLS(sts.bindIp+":443", sts.certFile, sts.keyFile, nil)
	if err != nil {
		log.Fatal("Failed to start the server. ", err)
	}
}

/*
iimport (
		"crypto/sha256"
			"fmt"
				"io"
					"log"
						"os"
					)

					func main() {
*/
