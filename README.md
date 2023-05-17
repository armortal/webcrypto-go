# webcrypto-go
An implementation of the W3C Web Cryptography API specification (https://w3c.github.io/webcrypto/) for Go.

## Background

The Web Cryptography API is an open standard developed by the W3C and *defines a low-level interface to interacting with cryptographic key material that is managed or exposed by user agents*.

Although the Web Cryptography API was developed for front-end applications, the way cryptographic logic is implemented in applications across languages is unique to the language itself. This library aims to keep these operations consistent across languages, in this case Golang, so that users can use documentation and knowledge from a well known open-standard to develop their applications easily and consistently. Cryptography is hard, and we hope this library can help all developers on their cryptographic journey.

The documentation and references used throughout this library come from the amazing authors at:
- [W3C Web Cryptography API Specification](https://w3c.github.io/webcrypto/)
- [Mozilla Web Crypto API Docs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

