# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Changed: Split `SimpleJWT\Crypt` namespace into multiple namespaces, one
  for each algorithm type (#60)
- Changed: `JWT` and `JWE` now derives from a common parent class `Token`
- Changed: Improved ASN.1 processing code (#68)
- Changed: Util::base64url_decode() will now throw
  `\UnexpectedValueException` instead of returning false if the input
  cannot be decoded
- Removed: Helper::getObject() and Helper::getJWTObject() have been
  replaced by Helper::decode() and Helper::decodeFully() respectively

## 0.6.3

- Deprecated: Helper::getObject() and Helper::getJWTObject() have been
  replaced by Helper::decode() and Helper::decodeFully() respectively,
  and will be removed in future versions

## 0.6.2

- Changed: Updated `symfony/console` package version
- Fixed: Compatibility with PHP 8.1 when using ECDH (#58)

## 0.6.1

- Changed: JWT::deserialise() no longer takes a `$format` parameter (which
  is already ignored)
- Changed: KeyFactory::create() now throws a KeyException if the supplied key
  cannot be decoded
- Changed: OpenSSLSig::getKeyCriteria() now throws an UnexpectedValueException
  if the supplied algorithm (`alg` header) is not valid
- Deprecated: Helper::getJWTObject() now ignores the `$jwe_kid` parameter
  and will be removed in future versions
- Fixed: API documentation for better static analysis checks

## 0.6.0

- Added: Support for Elliptic Curve Diffie-Hellman Ephemeral Static algorithms
- Added: JWT::tokenHash() to calculate OpenID Connect access token hash values
- Changed: When parsing multi-recipient JWTs and JWEs without corresponding
  key, the error code for InvalidTokenException was changed from
  TOKEN_PARSE_ERROR to SIGNATURE_VERIFICATION_ERROR (for JWSs) and
  DECRYPTION_ERROR (for JWEs), so that they are consistent with their
  single-recipient equivalents
- Fixed: Decoding JSON formatted JWEs and JWKs
- Fixed: Parsing multi-recipient JWTs and JWEs

## 0.5.3

- Fixed: typos in documentation leading to deprecation error (#39)
- Fixed: incorrect treatment of recipients object in JWE
- Removed: support for PHP 5

## 0.5.2

- Fixed: Undefined index when calling JWT::deserialise() and
  JWE::decrypt() with an unrecognised token format (#37)

## 0.5.1

- Added: Support for PHP 8 (#35)

## 0.5.0

- Added: Support for AES GCM family of algorithms
- Added: Support for Elliptic Curve Diffie-Hellman key derivation
  algorithm
- Changed: SimpleJWT\JWT::decode() no longer supports $format parameter
  (format is automatically detected)
- Changed: SimpleJWT\JWT::deserialise() no longer supports $format parameter
  (format is automatically detected)
- Changed: Return value of SimpleJWT\JWT::deserialise() changed
- Changed: SimpleJWT\JWE::decrypt() no longer supports $format parameter
  (format is automatically detected)
- Removed: SimpleJWT\Keys\Key::getSignature()
- Fixed: Autoload issue in jwkstool (#31)

## 0.4.2

- Fixed: Uninitialised values in SimpleJWT\JWT::deserialise() for JWTs encoded
  in JSON serialisation format (#29)
- Note: Arguments and/or return values for SimpleJWT\JWT::deserialise() may change
  in the next release

## 0.4.1

- Fixed: Composer dependencies on `symfony/console` for PHP 7 compatibility
  (#22)

## 0.4.0

- Changed: jwkstool build process
- Fixed: Syntax error in SimpleJWT\JWE::decrypt()
- Fixed: Arguments for SimpleJWT\JWT::deserialise()
- Deprecated: SimpleJWT\Keys\Key::getSignature() - use 
   SimpleJWT\Keys\Key::getThumbnail() instead

## 0.3.1

- Fixed undefined variable error when using JWE with a symmetric key (#19)
- Fixed Util::packInt64() when running 32-bit PHP 7
- Fixed missing time variable in InvalidTokenException
- More specific PHP version specification requirements in composer.json
- Refactored Util::random_bytes() to specify file-based entropy source
  for Unix-like systems

## 0.3.0

- Refactored key signature methodology to align with
  [RFC 7638](https://tools.ietf.org/html/rfc7638)
- Fixed typo in documentation

## 0.2.5

- Fixed incorrect handling of kid when using symmetric encryption (#13)
- Enhanced documentation
- Refactored coding style

## 0.2.4

- Fixed support for RSA-OAEP-256
- Fixed incorrect encoding of RSA keys into PEM (#10)

## 0.2.2

- Fixed incorrect decoding of PEM-encoded EC private keys (#8)
- Improved decoding of PEM-encoded RSA keys
- Enhanced tests

## 0.2.1

- Refactored code to add deserialise function

## 0.1.6

- Support newer versions of OpenSSL used in PHP 7, which uses lowercase
  cipher and message digest names (#7)

## 0.1.5

- Fixed namespace error in documentation blocks (#3)

## 0.1.4

- Fixed syntax error when throwing exception as a result of an invalid
  COMPACT_FORMAT token (#1)

## 0.1.3

- Fixed bug in jwkstool in referencing renamed method in KeySet

## 0.1.2

- Fixed bug caused by dependency issues with `symfony/composer`.  The   of this library is now locked to 2.7.*

## 0.1.1

- Enhanced compatibility with PHP 7

## 0.1.0

- Initial release
