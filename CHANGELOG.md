# Changelog

All notable changes to this project will be documented in this file.

## Version 0.5.1

- Added: Support for PHP 8 (#35)

## Version 0.5.0

- Added: Support for AES GCM family of algorithms
- Changed: SimpleJWT\JWT::decode() no longer supports $format parameter
  (format is automatically detected)
- Changed: SimpleJWT\JWT::deserialise() no longer supports $format parameter
  (format is automatically detected)
- Changed: Return value of SimpleJWT\JWT::deserialise() changed
- Changed: SimpleJWT\JWE::decrypt() no longer supports $format parameter
  (format is automatically detected)
- Removed: SimpleJWT\Keys\Key::getSignature()
- Fixed: Autoload issue in jwkstool (#31)

## Version 0.4.2

- Fixed: Uninitialised values in SimpleJWT\JWT::deserialise() for JWTs encoded
  in JSON serialisation format (#29)
- Note: Arguments and/or return values for SimpleJWT\JWT::deserialise() may change
  in the next release

## Version 0.4.1

- Fixed: Composer dependencies on `symfony/console` for PHP 7 compatibility
  (#22)

## Version 0.4.0

- Changed: jwkstool build process
- Fixed: Syntax error in SimpleJWT\JWE::decrypt()
- Fixed: Arguments for SimpleJWT\JWT::deserialise()
- Deprecated: SimpleJWT\Keys\Key::getSignature() - use 
   SimpleJWT\Keys\Key::getThumbnail() instead

## Version 0.3.1

- Fixed undefined variable error when using JWE with a symmetric key (#19)
- Fixed Util::packInt64() when running 32-bit PHP 7
- Fixed missing time variable in InvalidTokenException
- More specific PHP version specification requirements in composer.json
- Refactored Util::random_bytes() to specify file-based entropy source
  for Unix-like systems

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
