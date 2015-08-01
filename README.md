# SimpleJWT

SimpleJWT is a simple JSON web token library written in PHP.

## Features

- JSON web token [RFC7519](http://tools.ietf.org/html/rfc7519)
  and JSON web signatures [RFC7515](http://tools.ietf.org/html/rfc7515)
- JSON web keys [RFC7517](http://tools.ietf.org/html/rfc7517)
- Signature algorithms
    * HMAC family (HS256, HS384, HS512)
    * RSA family (RS256, RS384, RS512)
    * ECDSA family (ES256, ES384, ES512)

## Requirements

- PHP 5.3.9 or later
- `hash` extension
- `openssl` extension

## Installation

You can install via [Composer](http://getcomposer.org/).

```json
{
    "require": {
        "kelvinmo/simplejwt": "dev-master"
    }
}
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
  ```

### Creating a JWT

To create a JWT, set up the desired headers and claims as separate arrays, then
create a `JWT` object:

```php
// Note $headers['alg'] is required
$headers = array('alg' => 'HS256', 'typ' => 'JWT');
$claims = array('iss' => 'me', 'exp' => 1234567);
$jwt = new SimpleJWT\JWT($headers, $claims);
```

The JWT can then be signed and encoded:

```php
try {
    print $jwt->encode($set);
} catch (\RuntimeException $e) {

}
```

### Verfiying a JWT

To consume and verify a JWT, use the decode function:

```php
try {
    $jwt = SimpleJWT\JWT::decode('abc.def.ghigjghr');
} catch (SimpleJWT\InvalidTokenException $e) {

}

print $jwt->getHeader('alg');
print $jwt->getClaim('sub');
```

## License

BSD 3 clause
