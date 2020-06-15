# Changelog

## Version 0.3.0

- Refactored key signature methodology to align with
  [RFC 7638](https://tools.ietf.org/html/rfc7638)
- Fixed typo in documentation

## Version 0.2.5

- Fixed incorrect handling of kid when using symmetric encryption (#13)
- Enhanced documentation
- Refactored coding style

## Version 0.2.3/4

- Fixed support for RSA-OAEP-256
- Fixed incorrect encoding of RSA keys into PEM (#10)

## Version 0.2.2

- Fixed incorrect decoding of PEM-encoded EC private keys (#8)
- Improved decoding of PEM-encoded RSA keys
- Enhanced tests

## Version 0.2.0/1

- Refactored code to add deserialise function

## Version 0.1.6

- Support newer versions of OpenSSL used in PHP 7, which uses lowercase
  cipher and message digest names (#7)

## Version 0.1.5

- Fixed namespace error in documentation blocks (#3)

## Version 0.1.4

- Fixed syntax error when throwing exception as a result of an invalid
  COMPACT_FORMAT token (#1)

## Version 0.1.3

- Fixed bug in jwkstool in referencing renamed method in KeySet

## Version 0.1.2

- Fixed bug caused by dependency issues with `symfony/composer`.  The version
  of this library is now locked to 2.7.*

## Version 0.1.1

- Enhanced compatibility with PHP 7

## Version 0.1.0

- Initial release
