package main
 
import (
    "fmt"
    "encoding/base64"
    "path/filepath"
    "flag"
//    "errors"
    "net/http"
    "io/ioutil"
    "os"
    "io"
//    "bytes"
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
var asrtstr = flag.String("a", "none", "Comma separated ssertions about the file")


func main() {

  flag.Parse()

  if *asrtstr == "none" && *query == false {
	fmt.Println("command must include a query (-q) or an assertion (-a)")
  }else{
   if *asrtstr != "none" && *query {
	fmt.Println("command cannot include both a query (-q) and an assertion (-a)")
   }else{




    rsa_file:=fmt.Sprintf("%s/.ssh/rputn_rsa",os.Getenv("HOME"))
    if _, err := os.Stat(rsa_file); err == nil {
      rputn_rsa, _ := ioutil.ReadFile(rsa_file)
      block, _ := pem.Decode(rputn_rsa)
      rsakey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

      files, _ := filepath.Glob(*hashfiles)
      for _, f:= range files{
        if *verbose {
  	  fmt.Printf("Hashing: %s : ",f)
        }

        fhash := sha256.New224()
        fbytes, _ := ioutil.ReadFile(f)
        io.WriteString(fhash,string(fbytes))
        fhstr := base64.StdEncoding.EncodeToString(fhash.Sum(nil))
	fmt.Println(fhstr)


	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(fhash.Sum(nil))
	digest := h.Sum(nil)
	signresult, _ :=  rsa.SignPKCS1v15(rand.Reader, rsakey, hashFunc, digest)
        astr := base64.StdEncoding.EncodeToString(signresult)
	fmt.Println(astr)


        hloc := ""
	if *query {
          hloc = fmt.Sprintf("http://%s:%d/q?%s",*hashrepo,*hashport,fhstr)
	}else{
          hloc = fmt.Sprintf("http://%s:%d/a?%s",*hashrepo,*hashport,fhstr)
	}
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
        }
      }



    }else{
      fmt.Printf("Please generate a reputation public/private key pair, e.g.:\n#ssh-keygen -t rsa -C \"<username>@<hostname>\" -f ~/.ssh/rputn_dsa\n")
    }
   }
  }
}