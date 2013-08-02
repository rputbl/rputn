package main
 
import (
    "fmt"
    "errors"
    "net/url"
    "encoding/base64"
//    "encoding/hex"
    "path/filepath"
    "flag"
    "net/http"
    "io/ioutil"
    "os"
    "io"
//    "bytes"
    "strings"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    _ "crypto/sha1"
    "crypto/x509"
    "encoding/pem"
    "crypto/sha256"

    )

var hashrepo = flag.String("h", "rputbl.com", "The hash repository address")
var hashport = flag.Int("p", 8082, "The hash repository port")
var hashfiles = flag.String("f", "*", "The hash repository file(s)")  
var verbose =  flag.Bool("v", false, "Verbose logging")
var query =  flag.Bool("q", false, "Query hash of file")
var introduce =  flag.Bool("i", false, "Introduce myself to the hash repository")
var asrtstr = flag.String("a", "none", "Comma separated ssertions about the file")


func sha256base64( item []byte ) (string, []byte) {

      phash := sha256.New224()
      io.WriteString(phash,string(item))
      phashbytes:=phash.Sum(nil)
      return base64.StdEncoding.EncodeToString(phashbytes), phashbytes
}

func sign64(rsakey *rsa.PrivateKey, item []byte)(string, []byte){

	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(item)
	digest := h.Sum(nil)
	signresult, _ :=  rsa.SignPKCS1v15(rand.Reader, rsakey, hashFunc, digest)
	return base64.StdEncoding.EncodeToString(signresult), signresult
}


func getPKI() (*rsa.PrivateKey, []byte, error){

  rsa_file:=fmt.Sprintf("%s/.ssh/rputn_rsa",os.Getenv("HOME"))
  rsapub_file:=fmt.Sprintf("%s/.ssh/rputn_rsa.pub",os.Getenv("HOME"))

  _, err := os.Stat(rsa_file)
  if err == nil {
    _, err = os.Stat(rsapub_file)
  }
  if err != nil {
    return nil, nil, errors.New("Please generate a reputation public/private key pair, e.g.:\n#ssh-keygen -t rsa -C \"<username>@<hostname>\" -f ~/.ssh/rputn_dsa\n")
  }

  rputn_rsa, _ := ioutil.ReadFile(rsa_file)
  rputn_rsa_pub, _ := ioutil.ReadFile(rsapub_file)
  block, _ := pem.Decode(rputn_rsa)
  rsakey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

  return rsakey, rputn_rsa_pub, nil
}

func escapeSpaces(in []byte)[]byte{
    return []byte(strings.Replace(string(in), " ", "!", -1))
}

func unEscapeSpaces(in []byte)[]byte{
    return []byte(strings.Replace(string(in), "!", " ", -1))
}

func processFiles() error {

  flag.Parse()

  if *asrtstr == "none" && *query == false && *introduce == false{
    return errors.New("command must include a query (-q) or an assertion (-a) or an introduction (-i)")
  }

  if *asrtstr != "none" && ( *query || *introduce) {
    return errors.New("command must only be a query (-q) or an assertion (-a) or an introduction (-i)")
  }

  rsakey, rputn_rsa_pub, err := getPKI()
  if err != nil {
    return err
  }

  phstr, _ := sha256base64( rputn_rsa_pub )

  hloc := ""


  if *introduce {
        hloc = fmt.Sprintf("http://%s:%d/i?%s&%s",*hashrepo,*hashport,phstr,url.QueryEscape(string(rputn_rsa_pub)))
        _ , _ = doRequest( hloc )
  }else{

    files, _ := filepath.Glob(*hashfiles)
    for _, f:= range files{
        if *verbose {
  	  fmt.Printf("Hashing: %s : ",f)
        }

        fhstr, fhbytes := sha256base64( []byte(f) )



	if *query {
          hloc = fmt.Sprintf("http://%s:%d/q?%s",*hashrepo,*hashport,fhstr)
	}

	if *introduce {
          hloc = fmt.Sprintf("http://%s:%d/i?%s&%s",*hashrepo,*hashport,phstr,url.QueryEscape(string(rputn_rsa_pub)))
	}

        if  *asrtstr != "none" {
	  combinedBytes:= append(fhbytes, *asrtstr...)
	  signresultstr, _ := sign64(rsakey, combinedBytes)

	  if 1==2{
            hloc = fmt.Sprintf("http://%s:%d/a?%s&%s&%s&%s",*hashrepo,*hashport,fhstr,phstr,*asrtstr,signresultstr)
	  }
          hloc = fmt.Sprintf("http://%s:%d/a?%s&%s&%s&%s",*hashrepo,*hashport,fhstr,phstr,*asrtstr,"x")
	}
	

        _, _ = doRequest( hloc )
    }
  }
  return nil
}

func doRequest(hloc string)(string,error){

	rval:=""
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
	    rval=string(contents)
        }

	return rval,err
}




func main() {
  err := processFiles()
  if err != nil{
     fmt.Println("%s",err)
  }
}