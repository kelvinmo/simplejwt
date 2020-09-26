# SimpleJWT

SimpleJWT is a simple JSON web token library written in PHP.

[![Latest Stable Version](https://poser.pugx.org/kelvinmo/simplejwt/v/stable)](https://packagist.org/packages/kelvinmo/simplejwt)
[![CI](https://github.com/kelvinmo/simplejwt/workflows/CI/badge.svg)](https://github.com/kelvinmo/simplejwt/actions?query=workflow%3ACI)

## Features

- JSON web token [RFC7519](http://tools.ietf.org/html/rfc7519),
  JSON web signatures [RFC7515](http://tools.ietf.org/html/rfc7515)
  and JSON web encryption [RFC7516](http://tools.ietf.org/html/rfc7516)
- JSON web keys [RFC7517](http://tools.ietf.org/html/rfc7517)
- Signature algorithms
    * HMAC family (HS256, HS384, HS512)
    * RSA family (RS256, RS384, RS512)
    * ECDSA family (ES256, ES384, ES512)
- Key management algorithms
    * Key agreement or direct encryption
    * RSAES-PKCS1-v1_5 (RSA1_5)
    * RSAES with OAEP (RSA-OAEP, RSA-OAEP-256)
    * AES key wrap (A128KW, A192KW, A256KW)
    * PBES2 (PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW)
- Content encryption algorithms
    * AES_CBC_HMAC_SHA2 family (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512)
    * AES GCM family (A128GCM, A192GCM, A256GCM) - requires PHP 7.1 or later

## Requirements

- PHP:
    * PHP 7.1.0 or later; or
    * PHP 5.4.0 or later
- `hash` extension
- `openssl` extension

## Installation

You can install via [Composer](http://getcomposer.org/).

```sh
composer require kelvinmo/simplejwt
```

## Usage

### Key set

Keys used to sign or verify a JWT must firstly be added to a KeySet.  You
can add keys in the following ways:

1. By loading a JSON object formatted as a JWK Set object as per [RFC7517](http://tools.ietf.org/html/rfc7517):

  ```php
  $set = new SimpleJWT\Keys\KeySet();
  $set->load(file_get_contents('private.json'));
  ```

2. By adding a key manually:

  ```php
  $set = new SimpleJWT\Keys\KeySet();

  // JWK format
  $key = new SimpleJWT\Keys\RSAKey(file_get_contents('jwk.json'), 'json');

  // PEM format - note raw key only, no X.509 certificates
  $key = new SimpleJWT\Keys\RSAKey(file_get_contents('rsa.pem'), 'pem');

  $set->add($key);
  ```

3. For a secret used in HMAC signatures, directly:

  ```php
  $set = SimpleJWT\Keys\KeySet::createFromSecret('secret123');

  // The above is a shortcut for the following:
  $set = new SimpleJWT\Keys\KeySet();
  $key = new SimpleJWT\Keys\SymmetricKey('secret123', 'bin');
  $set->add($key);
  ```

### Creating a JWT

To create a JWT, set up the desired headers and claims as separate arrays, then
create a `JWT` object:

```php
// Note $headers['alg'] is required
$headers = ['alg' => 'HS256', 'typ' => 'JWT'];
$claims = ['iss' => 'me', 'exp' => 1234567];
$jwt = new SimpleJWT\JWT($headers, $claims);
```

The JWT can then be signed and encoded:

```php
try {
    print $jwt->encode($set);
} catch (\RuntimeException $e) {

}
```

By default, SimpleJWT will automatically include a `kid` (Key ID) header and
a `iat` (Issued At) claim in all JWTs.  If the key used to sign the JWT does
not have a `kid` assigned (e.g. if it is imported from a PEM file), a `kid`
is generated.  You can disable this behaviour by specifying `$auto_complete`
to false when calling `SimpleJWT\JWT::encode()`.

### Verifying a JWT

To consume and verify a JWT, use the decode function.  Note that you will need
to supply the expected `alg` parameter that has been previously agreed out-of-band.

```php
try {
    $jwt = SimpleJWT\JWT::decode('abc.def.ghigjghr', $set, 'HS256');
} catch (SimpleJWT\InvalidTokenException $e) {

}

print $jwt->getHeader('alg');
print $jwt->getClaim('sub');
```

### Deserialising a JWT

You can also deserialise a JWT without verifying it using the deserialise function.
**Note that you should not trust the contents of the data contained in a JWT without verifying them.**

```php
try {
    $result = SimpleJWT\JWT::deserialise('abc.def.ghigjghr');
} catch (SimpleJWT\InvalidTokenException $e) {

}

print $result['claims']['sub'];
print $result['signatures'][0]['headers']['alg'];
print $result['signatures'][0]['signing_input'];  // abc.def
print $result['signatures'][0]['signature'];      // ghigjghr
// Additional indices under $result['signatures'] if the JWT has more than
// one signature
```

### Creating a JWE

To create a JWE, set up the desired header array and plaintext, then
create a `JWE` object:

```php
// Note $headers['alg'] and $headers['enc'] are required
$headers = ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A128CBC-HS256'];
$plaintext = 'This is the plaintext I want to encrypt.';
$jwt = new SimpleJWT\JWE($headers, $plaintext);
```

The JWE can then be encrypted:

```php
try {
    print $jwt->encrypt($set);
} catch (\RuntimeException $e) {

}
```

### Decrypting a JWE

To decrypt a JWE, use the decrypt function:

```php
try {
    $jwt = SimpleJWT\JWE::decrypt('abc.def.ghi.klm.nop', $set, 'PBES2-HS256+A128KW');
} catch (SimpleJWT\InvalidTokenException $e) {

}

print $jwt->getHeader('alg');
print $jwt->getPlaintext();
```

## Licence

BSD 3 clause
