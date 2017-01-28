# badssl
A library for simplified certificate generation that is probably wrong, dirty, or just plain bad.

## model
This package models an (understandably) un(der)used TLS/SSL system where there are no intermediate authorities.
There are no certificate chains. There is only an authority and its immediate children.

# disclaimer
This package is intended to be used for testing, experimentation and development.
I do not know enough about TLS/SSL best practices, or the Go crypto/x509 package to write a package that provides secure TLS/SSL facilities.
In short: unless I discover otherwise, this package is considered *insecure*.
