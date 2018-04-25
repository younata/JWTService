# JWTService

Server-Side swift JWT encoder and key manager.

## Usage

TODO

## Symmetric Keys

TODO

## Asymmetric Keys

Currently, this package is optimized more for asymmetric (machine to machine) usages than symmetric (API authentication). This'll get updated later.

### Generating

Generating a key is relatively easy, here's what I did to generate the fixture keys used in the tests:

```sh
ssh-keygen -t rsa -b 4096 -f jwtRS256.key
# Don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
```

Which is copied from [this gist](https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9).
