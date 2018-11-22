// MIT License
//
// Copyright (c) 2018 the io-core authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
	//	"strconv"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

func getKeys( pkfn, bkfn string ) ( *rsa.PrivateKey, string) {

        pk, _ := ioutil.ReadFile(pkfn)
        bk, _ := ioutil.ReadFile(bkfn)
        bks := strings.TrimSpace(string(bk))
        privPem, _ := pem.Decode(pk)
        privPemBytes := privPem.Bytes
        parsedKey, _ := x509.ParsePKCS1PrivateKey(privPemBytes)


	return parsedKey, bks
}


func sign( contents []byte, asserts, format, pkeyf, bkeyf string ){

        al := strings.Split( asserts, ":")
	trail := "\n"
        for _, v := range al {
                trail=trail+v+"\n"
        }       
        
        now := fmt.Sprint(time.Now().Format("2006-01-02 15:04:05"))
        trail=trail+now+"\n"

	message := append(contents,trail...)
	hashed := sha256.Sum256(message)

	cl := "(*"
	cr := "*)"
	if format == "go" || format == "c" {
		cl = "//"
		cr = "//"
	}
	if format == "bash" || format == "csharp" {
		cl = " #"
		cr = "# "
	}

	parsedKey, bks := getKeys( pkeyf, bkeyf )

	signature, err := rsa.SignPKCS1v15(rand.Reader, parsedKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println(err)
	}

	spaces := "                                                                                                    "
	encoded := base64.StdEncoding.EncodeToString(signature)
	fmt.Println("\n"+ cl + "----Attest-1.0.0------------------------------------------------------------------------" + cr)
	for _, v := range al {
		fmt.Println(cl, v, spaces[:85-len(v)], cr)
	}
	fmt.Println(cl, now, spaces[:85-len(now)], cr)
	fmt.Println(cl + "----------------------------------------------------------------------------------------" + cr)
	fmt.Println(cl, encoded[0:86], cr+"\n"+cl, encoded[86:172], cr+"\n"+cl, encoded[172:258], cr+"\n"+cl, encoded[258:], cr)
	fmt.Println(cl + "----------------------------------------------------------------------------------------" + cr)
	fmt.Println(cl, bks[0:86], cr+"\n"+cl, bks[86:172], cr+"\n"+cl, bks[172:258], cr+"\n"+cl, bks[258:344], cr+"\n"+cl, bks[344:], spaces[:85-len(bks[344:])], cr)
	fmt.Println(cl + "----------------------------------------------------------------------------------------" + cr)
	
}

func main() {

        inFilePtr := flag.String("i", "-", "input file")
        aMessagePtr := flag.String("a", "signed", "attest message")
        formatPtr := flag.String("f", "oberon", "attest comment style")
        pkeyPtr := flag.String("p", os.Getenv("HOME")+"/.ssh/id_rsa", "path to rsa private key file")
        bkeyPtr := flag.String("b", os.Getenv("HOME")+"/.ssh/id_rsa.pub", "path to rsa public key file")
        checkPtr := flag.Bool("c", false, "check instead of sign")

        flag.Parse()

        iam := filepath.Base(os.Args[0])
        if iam == "acheck" {
                f := true
                checkPtr = &f
        }
        contents, _ := ioutil.ReadFile(*inFilePtr)

        if *checkPtr {
                fmt.Println("Checking signature integrity")
        }else{
                sign( contents, *aMessagePtr, *formatPtr, *pkeyPtr, *bkeyPtr )
        }
}


