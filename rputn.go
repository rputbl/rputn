// File: rputn.go
//
// Copyright (c) 2013 Charles Perkins
// 
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"errors"
	"fmt"
	"net/url"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

        "rputbl.com/hashbase"
)

var hashrepo = flag.String("h", "rputbl.com", "The hash repository address")
var hashport = flag.Int("p", 8082, "The hash repository port")
var hashfiles = flag.String("f", "*", "The hash repository file(s)")
var verbose = flag.Bool("v", false, "Verbose logging")
var query = flag.Bool("q", false, "Query hash of file")
var introduce = flag.Bool("i", false, "Introduce myself to the hash repository")
var asrtstr = flag.String("a", "none", "Comma separated ssertions about the file")

// process will introduce the user (based on an RSA public key) or
// generate hashes of local files and query a server about those hashes or
// generate hashes of local files and make assertions about those hashes
func process() error {

	flag.Parse()

	if *asrtstr == "none" && *query == false && *introduce == false {
		return errors.New("command must include a query (-q) or an assertion (-a) or an introduction (-i)")
	}

	if *asrtstr != "none" && (*query || *introduce) {
		return errors.New("command must only be a query (-q) or an assertion (-a) or an introduction (-i)")
	}

	rsakey, rputn_rsa_pub, err := hashbase.GetPKI()
	if err != nil {
		return err
	}

	phstr, _ := hashbase.Sha224base64(rputn_rsa_pub)

	hloc := ""

	if *introduce {
		hloc = fmt.Sprintf("http://%s:%d/i?%s&%s", *hashrepo, *hashport, phstr, url.QueryEscape(string(rputn_rsa_pub)))
		_, _ = doRequest(hloc)
	} else {

		files, _ := filepath.Glob(*hashfiles)
		for _, f := range files {
			if *verbose {
				fmt.Printf("Hashing: %s : ", f)
			}

			fhstr, fhbytes := hashbase.Sha224base64([]byte(f))

			if *query {
				hloc = fmt.Sprintf("http://%s:%d/q?%s", *hashrepo, *hashport, fhstr)
			}

			if *introduce {
				hloc = fmt.Sprintf("http://%s:%d/i?%s&%s", *hashrepo, *hashport, phstr, url.QueryEscape(string(rputn_rsa_pub)))
			}

			if *asrtstr != "none" {
				combinedBytes := append(fhbytes, *asrtstr...)
				signresultstr, _ := hashbase.Sign64(rsakey, combinedBytes)

				if 1 == 2 {
					hloc = fmt.Sprintf("http://%s:%d/a?%s&%s&%s&%s", *hashrepo, *hashport, fhstr, phstr, *asrtstr, signresultstr)
				}
				hloc = fmt.Sprintf("http://%s:%d/a?%s&%s&%s&%s", *hashrepo, *hashport, fhstr, phstr, *asrtstr, "x")
			}

			_, _ = doRequest(hloc)
		}
	}
	return nil
}

// doRequest performs the http query as declared in hloc.
func doRequest(hloc string) (string, error) {

	rval := ""
	response, err := http.Get(hloc)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	} else {
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("%s", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(contents))
		rval = string(contents)
	}

	return rval, err
}

// main function for rputn.
func main() {
	err := process()
	if err != nil {
		fmt.Println("%s", err)
	}
}
