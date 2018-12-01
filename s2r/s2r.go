/*
 * This file is in the public domain.
 * 
 * Originally written by Jan Schaumann <jschauma@netmeister.org> in
 * December 2013.
 *
 * Modified to be a callable library routine by Charles Perkins in 2018.
 *
 * This code serves as an example of how to convert an ssh(1) RSA public
 * key into PKCS8 format.  The program reads exactly one ssh RSA pubkey
 * from STDIN and spits out the PKCS8 formatted version.
 *
 * Some versions of ssh-keygen(1) can do the conversion:
 * ssh-keygen -e -m PKCS8 -f foo.pub
 *
 * If you want to use ssh(1) RSA keys for asymmetric encryption to share
 * secrets, take a look at: https://github.com/jschauma/jass
 *
 * For more details, please see:
 * http://www.netmeister.org/blog/ssh2pkcs8.html
 */

package s2r

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	//"io/ioutil"
	"log"
	"math/big"
	//"os"
	"strings"
)

const MAX_COLUMNS = 64

/*
 * Main
 */

func Translate(key string) string{
	var rv string

	/* An RSA SSH key can have leading key options (including quoted
	 * whitespace) and trailing comments (including whitespace).  We
	 * take a short cut here and assume that if it contains the known
	 * RSA pattern, then that field must be the actual key.  This
	 * would be a false assumption if one of the comments or options
	 * contained that same pattern, but anybody who creates such a key
	 * can fo screw themselves. */
	i:= strings.Index(key, "ssh-rsa AAAAB3NzaC1")
	if i < 0 {
		log.Fatal("Input does not look like a valid SSH RSA key.")
	}

	fields := strings.Split(key[i:], " ")
	decoded, err := base64.StdEncoding.DecodeString(fields[1]);
	if err != nil {
		log.Fatal("Unable to decode key: %v", err)
	}

	/* Based on:
	 * http://cpansearch.perl.org/src/MALLEN/Convert-SSH2-0.01/lib/Convert/SSH2.pm
	 * https://gist.github.com/mahmoudimus/1654254,
	 * http://golang.org/src/pkg/crypto/x509/x509.go
	 *
	 * The key format is base64 encoded tuples of:
	 * - four bytes representing the length of the next data field
	 * - the data field
	 *
	 * In practice, for an RSA key, we get:
	 * - four bytes [0 0 0 7]
	 * - the string "ssh-rsa" (7 bytes)
	 * - four bytes
	 * - the exponent
	 * - four bytes
	 * - the modulus
	 */
	n := 0
	var pubkey rsa.PublicKey
	for len(decoded) > 0 {
		var dlen uint32
		bbuf := bytes.NewReader(decoded[:4])
		err := binary.Read(bbuf, binary.BigEndian, &dlen)
		if err != nil {
			log.Fatal(err)
		}

		data := decoded[4:int(dlen)+4]
		decoded = decoded[4+int(dlen):]

		if (n == 0) {
			if ktype := fmt.Sprintf("%s", data); ktype != "ssh-rsa" {
				log.Fatal("Unsupported key type (%v).", ktype)
			}
		} else if (n == 1) {
			i := new(big.Int)
			i.SetString(fmt.Sprintf("0x%v", hex.EncodeToString(data)), 0)
			pubkey.E = int(i.Int64())
		} else if (n == 2) {
			i := new(big.Int)
			/* The value in this field is signed, so the first
			 * byte should be 0, so we strip it. */
			i.SetString(fmt.Sprintf("0x%v", hex.EncodeToString(data[1:])), 0)
			pubkey.N = i
			break
		}
		n += 1
	}

	enc, err := asn1.Marshal(pubkey)
	if err != nil {
		log.Fatal("Unable to marshal pubkey (%v): %v", pubkey, err)
	}
	bitstring := asn1.BitString{enc, len(enc) * 8}

	type AlgorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}

	var null = asn1.RawValue{ Tag: 5 }
	var pkid = AlgorithmIdentifier{ asn1.ObjectIdentifier{1,2,840,113549,1,1,1}, null }

	type keyseq struct {
		Algorithm AlgorithmIdentifier
		BitString asn1.BitString
	}
	ks := keyseq{ pkid, bitstring}

	enc, err = asn1.Marshal(ks)
	if err != nil {
		log.Fatal("Unable to marshal pubkey (%v): %v", pubkey, err)
	}

	

	rv = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n")
	out := base64.StdEncoding.EncodeToString(enc)
	for len(out) > MAX_COLUMNS {
		rv = rv + fmt.Sprintf("%v\n", out[:MAX_COLUMNS])
		out = out[MAX_COLUMNS:]
	}
	rv = rv + fmt.Sprintf("%v\n", out)
	rv=rv+fmt.Sprintf("-----END PUBLIC KEY-----\n")
	return rv
}

//----Attest-0.1.0------------------------------------------------------------------------//
// signed                                                                                 //
// 2018-11-30 18:50:25                                                                    //
//----------------------------------------------------------------------------------------//
// TVujmCgHlKgSTewoSgWrY+Htm22nnNqXgq6ryVDVvWlcE4JjtRoj9HejJyAaNHkccoDRPAOzpxlGWYMXKVXlrZ //
// Jtq3XSEB51/8dAVYF19lkx1oIq7HJCYG3DNY0P05lBvQ0aTsCg6NBisUg30ECFjNmfLLluhpgw6bxqpwRtrkeU //
// 1WHXal4YDswrr1yBJVatWuLlqviBlFT7K+fPJ8BZtocrCmCCWWh+WDvJlFMhhMaR472/iBsL8epLKR5S3TRNas //
// PNBmy/rk6n0vPQ9sOjTQfuorSNk++P6LmFGPOXFQiuLQtYduk6944QDd5jF33raDgN7m33la+JP5JAkSmpbg== //
//----------------------------------------------------------------------------------------//
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsrtAUhLbs/ELXgH3OJs0SKh7tSQE/gkPavHv4//tsLucTAN //
// C4mEjbjxKtFlZjji89GGvatnGu3DvAAz60VNEGBccezdn4rkcNpceKQe2KE2Kb13KM6VmrNl4Gj3+C278u0yKx //
// l07WpQCYJ1x6WU8Tnrs5oRSGvHzJVvkxbH7YfymnoXbDg2j8cWYX+zNR/aYvcX+6isZmqRDg+qZ1CK45UL0sO9 //
// GcSFyey3fGigzWGvBx9JujvsxL6aqX7yY+WtCbApeGLN4HYtrn4ueuKAQND5EYo0SEI2m+STt5eCdDBLFhG0jD //
// 5MO6T7o//Mg8qDeuiY5wpbcQdpVWmdWQQxMT chuck@kuracali.com                                //
//----------------------------------------------------------------------------------------//
