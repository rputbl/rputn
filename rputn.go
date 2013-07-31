package main
 
import (
    "fmt"
    "encoding/base64"
//    "encoding/hex"
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
var introduce =  flag.Bool("i", false, "Introduce myself to the hash repository")
var asrtstr = flag.String("a", "none", "Comma separated ssertions about the file")


func main() {

  flag.Parse()

  if *asrtstr == "none" && *query == false && *introduce == false{
	fmt.Println("command must include a query (-q) or an assertion (-a) or an introduction (-i)")
  }else{
   if *asrtstr != "none" && ( *query || *introduce) {
	fmt.Println("command must only be a query (-q) or an assertion (-a) or an introduction (-i)")
   }else{




    rsa_file:=fmt.Sprintf("%s/.ssh/rputn_rsa",os.Getenv("HOME"))
    rsapub_file:=fmt.Sprintf("%s/.ssh/rputn_rsa.pub",os.Getenv("HOME"))
    if _, err := os.Stat(rsa_file); err == nil {
     if _, err := os.Stat(rsapub_file); err == nil {

      rputn_rsa, _ := ioutil.ReadFile(rsa_file)
      rputn_rsa_pub, _ := ioutil.ReadFile(rsapub_file)
      block, _ := pem.Decode(rputn_rsa)
      rsakey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

      phash := sha256.New224()
      io.WriteString(phash,string(rputn_rsa_pub))
      phashbytes:=phash.Sum(nil)
      phstr := base64.StdEncoding.EncodeToString(phashbytes)

      files, _ := filepath.Glob(*hashfiles)
      for _, f:= range files{
        if *verbose {
  	  fmt.Printf("Hashing: %s : ",f)
        }

        fhash := sha256.New224()
        fbytes, _ := ioutil.ReadFile(f)
        io.WriteString(fhash,string(fbytes))
	fhashbytes:=fhash.Sum(nil)
        fhstr := base64.StdEncoding.EncodeToString(fhashbytes)

	
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(fhashbytes)
	h.Write([]byte(*asrtstr))
	digest := h.Sum(nil)
	signresult, _ :=  rsa.SignPKCS1v15(rand.Reader, rsakey, hashFunc, digest)
        signresultstr := base64.StdEncoding.EncodeToString(signresult)

        hloc := ""
	if *query {
          hloc = fmt.Sprintf("http://%s:%d/q?%s",*hashrepo,*hashport,fhstr)
	}else{
	  if *introduce {
            hloc = fmt.Sprintf("http://%s:%d/i?%s",*hashrepo,*hashport,"INTRODUCING!")
	  }else{
            hloc = fmt.Sprintf("http://%s:%d/a?%s&%s&%s",*hashrepo,*hashport,fhstr,*asrtstr,signresultstr)
	  }
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
    }else{
      fmt.Printf("Please generate a reputation public/private key pair, e.g.:\n#ssh-keygen -t rsa -C \"<username>@<hostname>\" -f ~/.ssh/rputn_dsa\n")
    }
   }
  }
}