<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2025
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

use SimpleJWT\Util\ASN1\DER;
use SimpleJWT\Util\ASN1\Value as ASN1Value;
use SimpleJWT\Util\BigNum;
use SimpleJWT\Util\Util;

/**
 * A class representing a public or private key in an elliptic curve key pair.
 */
class ECKey extends Key implements ECDHKeyInterface, PEMInterface {

    const KTY = 'EC';
    const COSE_KTY = 2;

    const PEM_RFC5915_PRIVATE = '/-----BEGIN EC PRIVATE KEY-----([^-:]+)-----END EC PRIVATE KEY-----/';

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
    public function __construct($data, string $format, ?string $password = null, ?string $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
            case 'json':
            case 'jwe':
                parent::__construct($data, $format, $password, $alg);
                break;
            case 'cbor':
                parent::__construct($data, $format, $password, $alg);
                if ($this->data['kty'] != self::COSE_KTY) throw new KeyException('Incorrect CBOR key type');
                $this->data['kty'] = self::KTY;
                $this->replaceDataKeys([ -1 => 'crv', -2 => 'x', -3 => 'y' ]);
                $this->replaceDataValues('crv', [ 1 => 'P-256', 2 => 'P-384', 3 => 'P-521', 8 => 'secp256k1' ]);
                break;
            case 'pem':
                /** @var string $data */
                $offset = 0;
                $jwk = [];
                $der = new DER();

                if (preg_match(Key::PEM_PUBLIC, $data, $matches)) {
                    /** @var string $binary */
                    $binary = base64_decode($matches[1]);
                    if ($binary == FALSE) throw new KeyException('Cannot read PEM key');

                    $seq = $der->decode($binary);

                    $algorithm = $seq->getChildAt(0)->getChildAt(0)->getValue();
                    if ($algorithm != self::EC_OID) throw new KeyException('Not EC key');

                    $curve_oid = $seq->getChildAt(0)->getChildAt(1)->getValue();
                    $curve = $this->getCurveNameFromOID($curve_oid);
                    if ($curve == null) throw new KeyException('Unrecognised EC parameter: ' . $curve_oid);

                    $len = self::$curves[$curve]['len'];

                    $point = $seq->getChildAt(1)->getValue();
                    if (strlen($point) != $len + 1) throw new KeyException('Incorrect public key length: ' . strlen($point));

                    if (ord($point[0]) != 0x04) throw new KeyException('Invalid public key');  // W

                    $x = substr($point, 1, $len / 2);
                    $y = substr($point, 1 + $len / 2);

                    $jwk['kty'] = self::KTY;
                    $jwk['crv'] = $curve;
                    $jwk['x'] = Util::base64url_encode($x);
                    $jwk['y'] = Util::base64url_encode($y);
                } elseif (preg_match(self::PEM_RFC5915_PRIVATE, $data, $matches)) {
                    /** @var string $binary */
                    $binary = base64_decode($matches[1]);
                    if ($binary == FALSE) throw new KeyException('Cannot read PEM key');

                    $seq = $der->decode($binary);

                    $jwk = self::parseASN1PrivateKey($seq);
                } elseif (preg_match(Key::PEM_PKCS8_PRIVATE, $data, $matches)) {
                    /** @var string $binary */
                    $binary = base64_decode($matches[1]);
                    if ($binary == FALSE) throw new KeyException('Cannot read PEM key');

                    $seq = $der->decode($binary);

                    $version = $seq->getChildAt(0)->getValue();
                    if ($version != 0) throw new KeyException('Invalid private key version: ' . $version);
                    
                    $key_oid = $seq->getChildAt(1)->getChildAt(0)->getValue();
                    if ($key_oid != self::EC_OID) throw new KeyException('Invalid key type: ' . $key_oid);

                    $curve_oid = $seq->getChildAt(1)->getChildAt(1)->getValue();
                    $curve = self::getCurveNameFromOID($curve_oid);
                    if ($curve == null) throw new KeyException('Unrecognised EC parameter: ' . $curve_oid);

                    $private_octet_string = $seq->getChildAt(2)->getValue();
                    $private_seq = $der->decode($private_octet_string);

                    $jwk = self::parseASN1PrivateKey($private_seq, $curve);
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

    public function getSize(): int {
        return 8 * strlen(Util::base64url_decode($this->data['x']));
    }

    public function isPublic(): bool {
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
    public function isValid(): bool {
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
     * @param ECDHKeyInterface $public_key the public key to check
     * @return bool true if the EC key is on the same curve
     * @see https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/
     */
    public function isOnSameCurve(ECDHKeyInterface $public_key): bool {
        if (!($public_key instanceof ECKey)) return false;
        if (!Util::secure_compare($this->getCurve(), $public_key->getCurve())) return false;

        return ($this->isValid() && $public_key->isValid());
    }

    public function getPublicKey(): ?KeyInterface {
        $data = [
            'kty' => $this->data['kty'],
            'crv' => $this->data['crv'],
            'x' => $this->data['x'],
            'y' => $this->data['y']
        ];
        if (isset($this->data['kid'])) $data['kid'] = $this->data['kid'];
        return new ECKey($data, 'php');
    }

    public function toPEM(): string {
        $der = new DER();
        $oid = self::$curves[$this->data['crv']]['oid'];
        if ($oid == null) throw new KeyException('Unrecognised EC curve');

        if ($this->isPublic()) {
            $seq = ASN1Value::sequence([
                ASN1Value::sequence([
                    ASN1Value::oid(self::EC_OID),
                    ASN1Value::oid($oid)
                ]),
                ASN1Value::bitString(chr(0x04) . Util::base64url_decode($this->data['x']) . Util::base64url_decode($this->data['y']))
            ]);
            $binary = $der->encode($seq);

            return wordwrap("-----BEGIN PUBLIC KEY-----\n" . base64_encode($binary) . "\n-----END PUBLIC KEY-----\n", 64, "\n", true);
        } else {
            $seq = ASN1Value::sequence([
                ASN1Value::integer(1),
                ASN1Value::octetString(Util::base64url_decode($this->data['d'])),
                ASN1Value::explicit(0, ASN1Value::oid($oid)),
                ASN1Value::explicit(1, ASN1Value::bitString(chr(0x04) . Util::base64url_decode($this->data['x']) . Util::base64url_decode($this->data['y'])))
            ]);
            $binary = $der->encode($seq);

            return wordwrap("-----BEGIN EC PRIVATE KEY-----\n" . base64_encode($binary) . "\n-----END EC PRIVATE KEY-----\n", 64, "\n", true);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getCurve(): string {
        return $this->data['crv'];
    }

    /**
     * {@inheritdoc}
     */
    public function createEphemeralKey(): ECDHKeyInterface {
        $crv = $this->getCurve();
        
        if (!isset(self::$curves[$crv])) throw new \InvalidArgumentException('Curve not found');
        $openssl_curve_name = self::$curves[$crv]['openssl'];

        $curves = openssl_get_curve_names();
        if ($curves == false) throw new KeyException('Cannot get openssl supported curves');

        if (!in_array($openssl_curve_name, $curves))
            throw new KeyException('Unable to create ephemeral key: unsupported curve');

        // Note openssl.cnf needs to be correctly configured for this to work.
        // See https://www.php.net/manual/en/openssl.installation.php for the
        // appropriate location of this configuration file
        $pkey = openssl_pkey_new([
            'curve_name' => $openssl_curve_name,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config' => dirname(__FILE__) . '/openssl.cnf'
        ]);
        if ($pkey === false) throw new KeyException('Unable to create ephemeral key (is openssl.cnf missing?)');
        
        // Note openssl.cnf needs to be correctly configured for this to work.
        // See https://www.php.net/manual/en/openssl.installation.php for the
        // appropriate location of this configuration file
        $result = openssl_pkey_export($pkey, $pem, null, [ 'config' => dirname(__FILE__) . '/openssl.cnf' ]);
        if ($result === false) throw new KeyException('Unable to create ephemeral key');

        return new ECKey($pem, 'pem');
    }

    /**
     * {@inheritdoc}
     */
    public function deriveAgreementKey(ECDHKeyInterface $public_key): string {
        assert(function_exists('openssl_pkey_derive'));

        if (!($public_key instanceof ECKey)) throw new KeyException('Key type does not match');
        if ($this->isPublic() || !$public_key->isPublic()) throw new KeyException('Parameter is not a public key');

        $public_key_res = openssl_pkey_get_public($public_key->toPEM());
        if ($public_key_res === false) throw new KeyException('Public key load error: ' . openssl_error_string());

        $private_key_res = openssl_pkey_get_private($this->toPEM());
        if ($private_key_res === false) throw new KeyException('Private key load error: ' . openssl_error_string());

        $result = openssl_pkey_derive($public_key_res, $private_key_res);
        if ($result === false) throw new KeyException('Key agreement error: ' . openssl_error_string());
        return $result;
    }

    protected function getThumbnailMembers(): array {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['crv', 'kty', 'x', 'y'];
    }

    /**
     * Parses an EC private key in DER form.
     * 
     * An EC private key is encoded using the ECPrivateKey type as per SEC 1.
     * 
     * @param ASN1Value $seq the ASN.1 sequence to parse
     * @param string $curve the name of the elliptic curve. If null, this will be
     * read from the sequence
     * @return array<string, mixed> the parsed private key data
     * @throws KeyException if an error occurs in parsing the key
     */
    protected static function parseASN1PrivateKey(ASN1Value $seq, $curve = null): array {
        $version = $seq->getChildAt(0)->getValue();
        if ($version != 1) throw new KeyException('Invalid private key version: ' . $version);

        $d = $seq->getChildAt(1)->getValue();

        if ($curve == null) {
            $curve_oid_param = $seq->getChildWithTag(0);
            if ($curve_oid_param == null) throw new KeyException('Missing EC curve parameter');
            $curve_oid = $curve_oid_param->getValue();
            $curve = self::getCurveNameFromOID($curve_oid);
            if ($curve == null) throw new KeyException('Unrecognised EC parameter: ' . $curve_oid);
        }

        if (!isset(self::$curves[$curve])) throw new KeyException('Curve not found');
        $len = self::$curves[$curve]['len'];

        $point = $seq->getChildWithTag(1)->getValue();
        if (strlen($point) != $len + 1) throw new KeyException('Incorrect private key length: ' . strlen($point));

        if (ord($point[0]) != 0x04) throw new KeyException('Invalid private key');  // W

        $x = substr($point, 1, $len / 2);
        $y = substr($point, 1 + $len / 2);

        return [
            'kty' => self::KTY,
            'crv' => $curve,
            'd' => Util::base64url_encode($d),
            'x' => Util::base64url_encode($x),
            'y' => Util::base64url_encode($y)
        ];
    }

    private static function getCurveNameFromOID(string $curve_oid): ?string {
        foreach (self::$curves as $crv => $params) {
            if ($params['oid'] == $curve_oid) return $crv;
        }
        return null;
    }
}

?>
