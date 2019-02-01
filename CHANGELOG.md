# Changelog

## Version 0.2.3

- Fixed support for RSA-OAEP-256

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
