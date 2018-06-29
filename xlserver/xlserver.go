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
	"strings"
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
		fmt.Fprintf(os.Stdout, "Usage of %s:\n", os.Args[0])
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
	return strings.ToLower(hex.EncodeToString(h.Sum(nil))), nil
}

func writeResponse(w http.ResponseWriter, resp string) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(resp))
}

func checkHandler(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	// We expect only single values per query parameter.
	// Thus we use Get instead of operator [].
	app := q.Get("app")
	ver := q.Get("ver")
	csum := q.Get("csum")

	if app == "" || ver == "" || csum == "" {
		writeResponse(w, "Not good")
		log.Println("Error: Received invalid query:", req.URL.RawQuery)
		return
	}

	log.Println("Processing query:", req.URL.RawQuery)

	fname := ver + ".server.class"
	calc_csum, err := getFileChecksum(fname)
	if err != nil {
		writeResponse(w, "Not good")
		log.Println("Error: Couldn't calculate checksum for file.", err)
		return
	} else if calc_csum != csum {
		writeResponse(w, "Not good")
		log.Println("Error: Checksum doesn't match for file:", fname)
		return
	}

	log.Println("Verification success for query:", req.URL.RawQuery)

	writeResponse(w, "XGFqCq6xm0gtFlbLDM0wRa1dm3FShwBerKhvebzA6So")
}

func main() {
	sts := getCommandLineSettings()
	log.SetPrefix("xlserver: ")
	http.HandleFunc("/check", checkHandler)
	err := http.ListenAndServeTLS(sts.bindIp+":443", sts.certFile, sts.keyFile, nil)
	if err != nil {
		log.Fatal("Error: Failed to start the server.", err)
	}
}
