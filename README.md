# attest
a tool to digitally sign source code as a comment at the bottom of the file
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

$ ./attest -a "signed:original" -i ./attest.go -f go
hashing ./attest.go attesting signed:original in go format
//----Attest-1.0.0------------------------------------------------------------------------//
// signed                                                                                 //
// original                                                                               //
// 2018-11-22 08:40:13                                                                    //
//----------------------------------------------------------------------------------------//
// U9HtN5FGZRYsrIZFdA2hUzEf+YI92eAUHQx2pS45pJ1urETb6Lj60WDDrwdiXYihwTZS3FSWhYYXn15chC0xiV //
// KA7O4vxeX+P0mm4gxM8+U2WBLGmltuUqKbxHsQFMWC25kmhqHaJFqyOErI6QrCVyCMO09GvvGTWZnjtQAJ37pv //
// zxRwL4VURet4iKD1A1FhkHligKLvvcWWrXnsfg2o21O4RqgpnfnTZM366hP64S8GJkqLtqBK+y8v5OYKxUVtRb //
// y02QrwmNLw1m6FMmhqP9DIshmjbVd5udNqcwcMdO68XnpiBPWCxQAlTmd2R1iqWiooWogNOWP5GBACplbR4g== //
//----------------------------------------------------------------------------------------//
// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsrtAUhLbs/ELXgH3OJs0SKh7tSQE/gkPavHv4//tsLucTAN //
// C4mEjbjxKtFlZjji89GGvatnGu3DvAAz60VNEGBccezdn4rkcNpceKQe2KE2Kb13KM6VmrNl4Gj3+C278u0yKx //
// l07WpQCYJ1x6WU8Tnrs5oRSGvHzJVvkxbH7YfymnoXbDg2j8cWYX+zNR/aYvcX+6isZmqRDg+qZ1CK45UL0sO9 //
// GcSFyey3fGigzWGvBx9JujvsxL6aqX7yY+WtCbApeGLN4HYtrn4ueuKAQND5EYo0SEI2m+STt5eCdDBLFhG0jD //
// 5MO6T7o//Mg8qDeuiY5wpbcQdpVWmdWQQxMT chuck@kuracali.com                                //
//----------------------------------------------------------------------------------------//
```
