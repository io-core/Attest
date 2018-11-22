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

func main() {

	inFilePtr := flag.String("i", "-", "input file")
	aMessagePtr := flag.String("a", "signed", "attest message")
	formatPtr := flag.String("f", "oberon", "attest comment style")
	pkeyPtr := flag.String("p", os.Getenv("HOME")+"/.ssh/id_rsa", "path to rsa private key file")
	bkeyPtr := flag.String("b", os.Getenv("HOME")+"/.ssh/id_rsa.pub", "path to rsa public key file")

	flag.Parse()

	message, _ := ioutil.ReadFile(*inFilePtr)
        
	message = message +"\n"
        for _, v := range al {
                message=message+v+"\n"
        }       
        
        now := fmt.Sprint(time.Now().Format("2006-01-02 15:04:05"))
        message=message+now+"\n"

	hashed := sha256.Sum256(message)
        al := strings.Split(*aMessagePtr, ":")

	cl := "(*"
	cr := "*)"
	if *formatPtr == "go" || *formatPtr == "c" {
		cl = "//"
		cr = "//"
	}
	if *formatPtr == "bash" || *formatPtr == "csharp" {
		cl = " #"
		cr = "# "
	}

	parsedKey, bks := getKeys( *pkeyPtr, *bkeyPtr )

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

//----Attest-1.0.0------------------------------------------------------------------------//
// signed                                                                                 //
// original                                                                               //
// 2018-11-22 08:47:55                                                                    //
//----------------------------------------------------------------------------------------//
// knJwZQ/bkpCMqEURSTCCzcAXTjJLKgikrN02i2/Jg0iQRE5AYN8OsJ/iuD50wDjZQZMxoLx+thyhQpZHY+AcWS //
// a1E6cPOJ9qz/GGJo472gFR230V3wQSokBsPFFzOP0s1meSuqMMFuuqbwfYGMolFApZDaMmzfkSKIYUmLIVe5t8 //
// p0Y09IyWJJH4xXv/Tp5fCwLcHK65jUHNLL/ueUqCqegwHZPQgpU9TCIrp2ViKH2wgUz3uBcMDmzk5Crk0xpgHw //
// O+wfP3nc05aPJNle04RRmRPC4YxtiyPsScz8sA+fvMjzPFEa9+FITS07YjCgDdc0ANxWcqMszsyqOB2iNZcQ== //
//----------------------------------------------------------------------------------------//
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsrtAUhLbs/ELXgH3OJs0SKh7tSQE/gkPavHv4//tsLucTAN //
// C4mEjbjxKtFlZjji89GGvatnGu3DvAAz60VNEGBccezdn4rkcNpceKQe2KE2Kb13KM6VmrNl4Gj3+C278u0yKx //
// l07WpQCYJ1x6WU8Tnrs5oRSGvHzJVvkxbH7YfymnoXbDg2j8cWYX+zNR/aYvcX+6isZmqRDg+qZ1CK45UL0sO9 //
// GcSFyey3fGigzWGvBx9JujvsxL6aqX7yY+WtCbApeGLN4HYtrn4ueuKAQND5EYo0SEI2m+STt5eCdDBLFhG0jD //
// 5MO6T7o//Mg8qDeuiY5wpbcQdpVWmdWQQxMT chuck@kuracali.com                                //
//----------------------------------------------------------------------------------------//
