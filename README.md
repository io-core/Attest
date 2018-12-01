# attest
a tool to digitally sign source code as a comment at the bottom of the file

```
$ echo 'echo "Hello from the shell script..."; echo "$1"; exit 0' > hello.sh
$ attest -f bash hello.sh >> hello.sh
```

# acheck
(a.k.a. attest -c) a tool to check the integrity of a signature attached to a file

```
$ acheck hello.sh
verify success!
$ perl -pi -e 's/Hello/Goodbye/g' hello.sh 
$ acheck hello.sh 
verify error: crypto/rsa: verification error
```

# ifaok
an example of checking the integrity of a shell script before executing it

```
$ ifaok hello.sh There
verify success!
Hello from the shell script...
There
```

# more info

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

$ ./attest -f go s2r/s2r.go >> s2r/s2r.go
$ ./attest -c s2r/s2r.go
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
