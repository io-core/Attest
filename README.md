# attest
a tool to digitally sign source code as a comment at the bottom of the file

Comment styles are defined for:

ada
actionscript
applescript
assembly
bash
c
c#
c++
clojure
coffeescript
css
delphi
erlang
f90
FORTRAN
go
haskell
haskellb
html
ios
java
javascript
lua
matlab
shell
modula2
oberon
objectivec
ocaml
pascal
perl
php
powershell
python
ruby
sql
scala
swift
tpascal
vb
xml


```
$ ./attest -h
Usage of ./attest:
  -a string
    	attest message (default "signed")
  -b string
    	path to rsa public key file (default "~/.ssh/id_rsa.pub")
  -f string
    	attest comment style (default "oberon")
  -i string
    	input file (default "-")
  -p string
    	path to rsa private key file (default "~/.ssh/id_rsa")

$ ./attest -f go -i s2r/s2r.go >> s2r/s2r.go
$ ./attest -c -i s2r/s2r.go
verify success!
$ tail -n 20 s2r/s2r.go 
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

```
