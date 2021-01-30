<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2021
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
use SimpleJWT\Util\Util;

/**
 * A class representing a public or private key in an elliptic curve key pair.
 */
class ECKey extends Key {

    const KTY = 'EC';

    const PEM_PRIVATE = '/-----BEGIN EC PRIVATE KEY-----([^-:]+)-----END EC PRIVATE KEY-----/';

    const EC_OID = '1.2.840.10045.2.1';
    const P256_OID = '1.2.840.10045.3.1.7';
    const SECP256K1_OID = '1.3.132.0.10';
    const P384_OID = '1.3.132.0.34';
    const P521_OID = '1.3.132.0.35';

    static $curves = [
        self::P256_OID => ['crv' => 'P-256', 'len' => 64],
        self::SECP256K1_OID => ['crv' => 'secp256k1', 'len' => 64],
        self::P384_OID => ['crv' => 'P-384', 'len' => 96],
        self::P521_OID => ['crv' => 'P-521', 'len' => 132],
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
     * @param string|array $data the key data
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
                    $der = base64_decode($matches[1]);

                    if ($der === FALSE) throw new KeyException('Cannot read PEM key');

                    $offset += ASN1::readDER($der, $offset, $value);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $value);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $algorithm);  // OBJECT IDENTIFIER - AlgorithmIdentifier

                    $algorithm = ASN1::decodeOID($algorithm);
                    if ($algorithm != self::EC_OID) throw new KeyException('Not EC key');

                    $offset += ASN1::readDER($der, $offset, $curve);  // OBJECT IDENTIFIER - parameters
                    $curve = ASN1::decodeOID($curve);
                    if (!isset(self::$curves, $curve)) throw new KeyException('Unrecognised EC parameter: ' . $curve);

                    $len = self::$curves[$curve]['len'];

                    $offset += ASN1::readDER($der, $offset, $point);  // BIT STRING - ECPoint
                    if (strlen($point) != $len + 1) throw new KeyException('Incorrect public key length: ' . strlen($point));

                    if (ord($point[0]) != 0x04) throw new KeyException('Invalid public key');  // W

                    $x = substr($point, 1, $len / 2);
                    $y = substr($point, 1 + $len / 2);

                    $jwk['kty'] = self::KTY;
                    $jwk['crv'] = self::$curves[$curve]['crv'];
                    $jwk['x'] = Util::base64url_encode($x);
                    $jwk['y'] = Util::base64url_encode($y);
                } elseif (preg_match(self::PEM_PRIVATE, $data, $matches)) {
                    $der = base64_decode($matches[1]);

                    if ($der === FALSE) throw new KeyException('Cannot read PEM key');

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $version);  // INTEGER

                    if (ord($version) != 1) throw new KeyException('Invalid private key version');

                    $offset += ASN1::readDER($der, $offset, $d);  // OCTET STRING [d]

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE[0]
                    $offset += ASN1::readDER($der, $offset, $curve);  // OBJECT IDENTIFIER - parameters
                    $curve = ASN1::decodeOID($curve);
                    if (!isset(self::$curves, $curve)) throw new KeyException('Unrecognised EC parameter: ' . $curve);

                    $len = self::$curves[$curve]['len'];

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE[1]
                    $offset += ASN1::readDER($der, $offset, $point);  // BIT STRING - ECPoint
                    if (strlen($point) != $len + 1) throw new KeyException('Incorrect private key length: ' . strlen($point));

                    if (ord($point[0]) != 0x04) throw new KeyException('Invalid private key');  // W

                    $x = substr($point, 1, $len / 2);
                    $y = substr($point, 1 + $len / 2);

                    $jwk['kty'] = self::KTY;
                    $jwk['crv'] = self::$curves[$curve]['crv'];
                    $jwk['d'] = Util::base64url_encode($d);
                    $jwk['x'] = Util::base64url_encode($x);
                    $jwk['y'] = Util::base64url_encode($y);
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
        $oid = $this->getOID($this->data['crv']);
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

    protected function getThumbnailMembers() {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['crv', 'kty', 'x', 'y'];
    }

    private function getOID($crv) {
        foreach (self::$curves as $oid => $params) {
            if ($params['crv'] == $crv) return $oid;
        }
        return null;
    }
}

?>
