package main
 
import (
    "fmt"
    "path/filepath"
    "flag"
//    "errors"
    "net/http"
    "io/ioutil"
    "os"
    "io"
    "crypto/sha256"
    )

var hashrepo = flag.String("h", "rputbl.com", "The hash repository address")
var hashport = flag.Int("p", 8082, "The hash repository port")
var hashfiles = flag.String("f", "*", "The hash repository file(s)")  
var verbose =  flag.Bool("v", false, "Verbose logging")

func main() {
    flag.Parse()
    hloc := fmt.Sprintf("http://%s:%d/q",*hashrepo,*hashport)

    files, _ := filepath.Glob(*hashfiles)

    for _, f:= range files{
      if *verbose {
  	fmt.Printf("Hashing: %s --",f)
      }

      fhash := sha256.New224()
      fbytes, _ := ioutil.ReadFile(f)
      io.WriteString(fhash,string(fbytes))
      fmt.Printf("% x", fhash.Sum(nil))

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
}