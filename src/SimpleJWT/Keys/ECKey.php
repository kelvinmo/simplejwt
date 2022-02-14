<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2022
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace SimpleJWT\Keys;

use SimpleJWT\Util\ASN1;
use SimpleJWT\Util\BigNum;
use SimpleJWT\Util\Util;

/**
 * A class representing a public or private key in an elliptic curve key pair.
 */
class ECKey extends Key {

    const KTY = 'EC';

    const PEM_RFC5915_PRIVATE = '/-----BEGIN EC PRIVATE KEY-----([^-:]+)-----END EC PRIVATE KEY-----/';
    const PEM_PKCS8_PRIVATE = '/-----BEGIN PRIVATE KEY-----([^-:]+)-----END PRIVATE KEY-----/';  // used by PHP 8.1

    const EC_OID = '1.2.840.10045.2.1';
    const P256_OID = '1.2.840.10045.3.1.7';
    const SECP256K1_OID = '1.3.132.0.10';
    const P384_OID = '1.3.132.0.34';
    const P521_OID = '1.3.132.0.35';

    // Curve parameters are from http://www.secg.org/sec2-v2.pdf
    /** @var array<string, mixed> $curves */
    static $curves = [
        'P-256' => [
            'oid' => self::P256_OID,
            'openssl' => 'prime256v1', // = secp256r1
            'len' => 64,
            'a' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
            'b' => '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
            'p' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
        ],
        'P-384' => [
            'oid' => self::P384_OID,
            'openssl' => 'secp384r1',
            'len' => 96,
            'a' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
            'b' => 'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF',
            'p' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
        ],
        'P-521' => [
            'oid' => self::P521_OID,
            'openssl' => 'secp521r1',
            'len' => 132,
            'a' => '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC',
            'b' => '0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
            'p' => '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        ],
        'secp256k1' => [
            'oid' => self::SECP256K1_OID,
            'openssl' => 'secp256k1',
            'len' => 64,
            'a' => '0000000000000000000000000000000000000000000000000000000000000000',
            'b' => '0000000000000000000000000000000000000000000000000000000000000007',
            'p' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
        ],
    ];

    /**
     * Creates an EC key.
     *
     * The supported formats are:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `jwe` - Encrypted JSON web key
     * - `pem` - the public or private key encoded in PEM (base64 encoded DER) format
     *
     * @param string|array<string, mixed> $data the key data
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     */
    public function __construct($data, $format, $password = null, $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
            case 'json':
            case 'jwe':
                parent::__construct($data, $format, $password, $alg);
                break;
            case 'pem':
                $offset = 0;
                $jwk = [];

                if (preg_match(Key::PEM_PUBLIC, $data, $matches)) {
                    /** @var string|bool $der */
                    $der = base64_decode($matches[1]);

                    if ($der === FALSE) throw new KeyException('Cannot read PEM key');

                    $offset += ASN1::readDER($der, $offset, $value);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $value);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $algorithm);  // OBJECT IDENTIFIER - AlgorithmIdentifier

                    $algorithm = ASN1::decodeOID($algorithm);
                    if ($algorithm != self::EC_OID) throw new KeyException('Not EC key');

                    $offset += ASN1::readDER($der, $offset, $curve_oid);  // OBJECT IDENTIFIER - parameters
                    $curve_oid = ASN1::decodeOID($curve_oid);
                    $curve = $this->getCurveNameFromOID($curve_oid);
                    if ($curve == null) throw new KeyException('Unrecognised EC parameter: ' . $curve_oid);

                    $len = self::$curves[$curve]['len'];

                    $offset += ASN1::readDER($der, $offset, $point);  // BIT STRING - ECPoint
                    if (strlen($point) != $len + 1) throw new KeyException('Incorrect public key length: ' . strlen($point));

                    if (ord($point[0]) != 0x04) throw new KeyException('Invalid public key');  // W

                    $x = substr($point, 1, $len / 2);
                    $y = substr($point, 1 + $len / 2);

                    $jwk['kty'] = self::KTY;
                    $jwk['crv'] = $curve;
                    $jwk['x'] = Util::base64url_encode($x);
                    $jwk['y'] = Util::base64url_encode($y);
                } elseif (preg_match(self::PEM_RFC5915_PRIVATE, $data, $matches)) {
                    /** @var string|bool $der */
                    $der = base64_decode($matches[1]);
                    if ($der === FALSE) throw new KeyException('Cannot read PEM key');

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $version);  // INTEGER

                    if (ord($version) != 1) throw new KeyException('Invalid private key version: ' . ord($version));

                    $offset += ASN1::readDER($der, $offset, $d);  // OCTET STRING [d]

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE[0]
                    $offset += ASN1::readDER($der, $offset, $curve_oid);  // OBJECT IDENTIFIER - parameters
                    $curve_oid = ASN1::decodeOID($curve_oid);
                    $curve = self::getCurveNameFromOID($curve_oid);
                    if ($curve == null) throw new KeyException('Unrecognised EC parameter: ' . $curve_oid);

                    $len = self::$curves[$curve]['len'];

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE[1]
                    $offset += ASN1::readDER($der, $offset, $point);  // BIT STRING - ECPoint
                    if (strlen($point) != $len + 1) throw new KeyException('Incorrect private key length: ' . strlen($point));

                    if (ord($point[0]) != 0x04) throw new KeyException('Invalid private key');  // W

                    $x = substr($point, 1, $len / 2);
                    $y = substr($point, 1 + $len / 2);

                    $jwk['kty'] = self::KTY;
                    $jwk['crv'] = $curve;
                    $jwk['d'] = Util::base64url_encode($d);
                    $jwk['x'] = Util::base64url_encode($x);
                    $jwk['y'] = Util::base64url_encode($y);
                } elseif (preg_match(self::PEM_PKCS8_PRIVATE, $data, $matches)) {
                    /** @var string|bool $der */
                    $der = base64_decode($matches[1]);
                    if ($der === FALSE) throw new KeyException('Cannot read PEM key');

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $version);  // INTEGER

                    if (ord($version) != 0) throw new KeyException('Invalid private key version: ' . ord($version));

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $key_oid);  // OBJECT IDENTIFIER - id-ecPublicKey

                    if (ASN1::decodeOID($key_oid) != self::EC_OID) throw new KeyException('Invalid key type: ' . ASN1::decodeOID($key_oid));

                    $offset += ASN1::readDER($der, $offset, $curve_oid);  // OBJECT IDENTIFIER - parameters
                    $curve_oid = ASN1::decodeOID($curve_oid);
                    $curve = self::getCurveNameFromOID($curve_oid);
                    if ($curve == null) throw new KeyException('Unrecognised EC parameter: ' . $curve_oid);

                    $len = self::$curves[$curve]['len'];

                    $offset += ASN1::readDER($der, $offset, $private_key);  // OCTET STRING [privateKey]

                    // Parse the octet string
                    $offset = 0;
                    $offset += ASN1::readDER($private_key, $offset, $data);  // SEQUENCE
                    $offset += ASN1::readDER($private_key, $offset, $version);  // INTEGER

                    if (ord($version) != 1) throw new KeyException('Invalid private key version: ' . ord($version));

                    $offset += ASN1::readDER($private_key, $offset, $d);  // OCTET STRING [d]

                    $offset += ASN1::readDER($private_key, $offset, $data);  // SEQUENCE[0]
                    $offset += ASN1::readDER($private_key, $offset, $point);  // BIT STRING - ECPoint

                    if (strlen($point) != $len + 1) throw new KeyException('Incorrect private key length: ' . strlen($point));

                    if (ord($point[0]) != 0x04) throw new KeyException('Invalid private key');  // W

                    $x = substr($point, 1, $len / 2);
                    $y = substr($point, 1 + $len / 2);

                    $jwk['kty'] = self::KTY;
                    $jwk['crv'] = $curve;
                    $jwk['d'] = Util::base64url_encode($d);
                    $jwk['x'] = Util::base64url_encode($x);
                    $jwk['y'] = Util::base64url_encode($y);
                } else {
                    throw new KeyException('Unrecognised key format');
                }

                parent::__construct($jwk);
                break;
            default:
                throw new KeyException('Incorrect format');
        }

        if (!isset($this->data['kty'])) $this->data['kty'] = self::KTY;
    }

    public function getSize() {
        return 8 * strlen(Util::base64url_decode($this->data['x']));
    }

    public function isPublic() {
        return !isset($this->data['d']);
    }

    /**
     * Checks whether this EC key is valid, in that its `x` and `y` values satisfies
     * the elliptic curve function specified by the `crv` value.
     * 
     * This check is required to prevent invalid curve attacks, whereby an
     * untrusted key contains `x` and `y` parameters are not on the curve, which
     * may result in differential attacks
     * 
     * @return bool true if the EC key is valid
     * @see https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/
     */
    public function isValid() {
        $x = new BigNum(Util::base64url_decode($this->data['x']), 256);
        $y = new BigNum(Util::base64url_decode($this->data['y']), 256);

        $crv = $this->data['crv'];
        $a = new BigNum(hex2bin(self::$curves[$crv]['a']), 256);
        $b = new BigNum(hex2bin(self::$curves[$crv]['b']), 256);
        $p = new BigNum(hex2bin(self::$curves[$crv]['p']), 256);

        // Check whether y^2 mod p = (x^3 + ax + b) mod p
        $y2modp = $y->powmod(new BigNum(2), $p);
        $x3axbmodp = $x->pow(new BigNum(3))->add($a->mul($x))->add($b)->mod($p);

        return ($y2modp->cmp($x3axbmodp) === 0);
    }

    /**
     * Checks whether another EC key is on the same curve as this key.
     * 
     * @param ECKey $public_key the public key to check
     * @return bool true if the EC key is on the same curve
     * @see https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/
     */
    public function isOnSameCurve($public_key) {
        if (!($public_key instanceof ECKey)) return false;
        if (!Util::secure_compare($this->data['crv'], $public_key->data['crv'])) return false;

        return ($this->isValid() && $public_key->isValid());
    }

    public function getPublicKey() {
        return new ECKey([
            'kid' => $this->data['kid'],
            'kty' => $this->data['kty'],
            'crv' => $this->data['crv'],
            'x' => $this->data['x'],
            'y' => $this->data['y']
        ], 'php');
    }

    public function toPEM() {
        $oid = self::$curves[$this->data['crv']]['oid'];
        if ($oid == null) throw new KeyException('Unrecognised EC curve');

        if ($this->isPublic()) {
            $der = ASN1::encodeDER(ASN1::SEQUENCE,
                ASN1::encodeDER(ASN1::SEQUENCE,
                    ASN1::encodeDER(ASN1::OID, ASN1::encodeOID(self::EC_OID))
                    . ASN1::encodeDER(ASN1::OID, ASN1::encodeOID($oid)),
                    false
                ) .
                ASN1::encodeDER(ASN1::BIT_STRING, chr(0x00) . chr(0x04) . Util::base64url_decode($this->data['x']) . Util::base64url_decode($this->data['y'])),
            false);

            return wordwrap("-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----\n", 64, "\n", true);
        } else {
            $der = ASN1::encodeDER(ASN1::SEQUENCE,
                ASN1::encodeDER(ASN1::INTEGER_TYPE, chr(0x01))
                . ASN1::encodeDER(ASN1::OCTET_STRING, Util::base64url_decode($this->data['d']))
                . ASN1::encodeDER(0x00, ASN1::encodeDER(ASN1::OID, ASN1::encodeOID($oid)), false, ASN1::CONTEXT_CLASS)
                . ASN1::encodeDER(0x01, ASN1::encodeDER(ASN1::BIT_STRING, chr(0x00) . chr(0x04) . Util::base64url_decode($this->data['x']) . Util::base64url_decode($this->data['y'])), false, ASN1::CONTEXT_CLASS),
            false);

            return wordwrap("-----BEGIN EC PRIVATE KEY-----\n" . base64_encode($der) . "\n-----END EC PRIVATE KEY-----\n", 64, "\n", true);
        }
    }

    /**
     * Gets the elliptic curve for the key.  The elliptic curve is specified in
     * the `crv` parameter.
     * 
     * @return string the elliptic curve
     */
    public function getCurve() {
        return $this->data['crv'];
    }

    protected function getThumbnailMembers() {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['crv', 'kty', 'x', 'y'];
    }

    private static function getCurveNameFromOID(string $curve_oid): ?string {
        foreach (self::$curves as $crv => $params) {
            if ($params['oid'] == $curve_oid) return $crv;
        }
        return null;
    }
}

?>
