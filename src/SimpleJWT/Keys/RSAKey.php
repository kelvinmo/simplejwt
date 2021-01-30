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
 * A class representing a public or private key in an RSA key pair.
 */
class RSAKey extends Key {

    const KTY = 'RSA';

    const PEM_PRIVATE = '/-----BEGIN RSA PRIVATE KEY-----([^-:]+)-----END RSA PRIVATE KEY-----/';
    const OID = '1.2.840.113549.1.1.1';

    /**
     * Creates an RSA key.
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
                    if ($algorithm != self::OID) throw new KeyException('Not RSA key');


                    $offset += ASN1::readDER($der, $offset, $value);  // NULL - parameters
                    $offset += ASN1::readDER($der, $offset, $value, true);  // BIT STRING
                    $offset += ASN1::readDER($der, $offset, $value);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $n);  // INTEGER [n]
                    $offset += ASN1::readDER($der, $offset, $e);  // INTEGER [e]

                    $jwk['kty'] = self::KTY;
                    $jwk['n'] = Util::base64url_encode(ASN1::intToUint($n));
                    $jwk['e'] = Util::base64url_encode($e);
                } elseif (preg_match(self::PEM_PRIVATE, $data, $matches)) {
                    $der = base64_decode($matches[1]);

                    if ($der === FALSE) throw new KeyException('Cannot read PEM key');

                    $offset += ASN1::readDER($der, $offset, $data);  // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $version);  // INTEGER

                    if (ord($version) != 0) throw new KeyException('Unsupported RSA private key version');

                    $offset += ASN1::readDER($der, $offset, $n);  // INTEGER [n]
                    $offset += ASN1::readDER($der, $offset, $e);  // INTEGER [e]
                    $offset += ASN1::readDER($der, $offset, $d);  // INTEGER [d]
                    $offset += ASN1::readDER($der, $offset, $p);  // INTEGER [p]
                    $offset += ASN1::readDER($der, $offset, $q);  // INTEGER [q]
                    $offset += ASN1::readDER($der, $offset, $dp);  // INTEGER [dp]
                    $offset += ASN1::readDER($der, $offset, $dq);  // INTEGER [dq]
                    $offset += ASN1::readDER($der, $offset, $qi);  // INTEGER [qi]
                    if (strlen($der) > $offset) ASN1::readDER($der, $offset, $oth);  // INTEGER [other]

                    $jwk['kty'] = self::KTY;
                    $jwk['n'] = Util::base64url_encode(ASN1::intToUint($n));
                    $jwk['e'] = Util::base64url_encode($e);
                    $jwk['d'] = Util::base64url_encode(ASN1::intToUint($d));
                    $jwk['p'] = Util::base64url_encode(ASN1::intToUint($p));
                    $jwk['q'] = Util::base64url_encode(ASN1::intToUint($q));
                    $jwk['dp'] = Util::base64url_encode(ASN1::intToUint($dp));
                    $jwk['dq'] = Util::base64url_encode(ASN1::intToUint($dq));
                    $jwk['qi'] = Util::base64url_encode(ASN1::intToUint($qi));
                }

                parent::__construct($jwk);
                break;
            default:
                throw new KeyException('Incorrect format');
        }

        if (!isset($this->data['kty'])) $this->data['kty'] = self::KTY;
    }

    public function getSize() {
        // The modulus is a signed integer, therefore ignore the first byte
        return 8 * (strlen(Util::base64url_decode($this->data['n'])) - 1);
    }

    public function isPublic() {
        return !isset($this->data['p']);
    }

    public function getPublicKey() {
        return new RSAKey([
            'kid' => $this->data['kid'],
            'kty' => $this->data['kty'],
            'n' => $this->data['n'],
            'e' => $this->data['e']
        ], 'php');
    }

    public function toPEM() {
        if ($this->isPublic()) {
            $der = ASN1::encodeDER(ASN1::SEQUENCE,
                ASN1::encodeDER(ASN1::SEQUENCE,
                    ASN1::encodeDER(ASN1::OID, ASN1::encodeOID(self::OID))
                    . ASN1::encodeDER(ASN1::NULL_TYPE),
                    false
                ) .
                ASN1::encodeDER(ASN1::BIT_STRING, chr(0x00).
                    ASN1::encodeDER(ASN1::SEQUENCE,
                        ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['n'])))
                         . ASN1::encodeDER(ASN1::INTEGER_TYPE, Util::base64url_decode($this->data['e'])),
                        false
                    )
                ),
            false);

            return wordwrap("-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----\n", 64, "\n", true);
        } else {
            $der = ASN1::encodeDER(ASN1::SEQUENCE,
                ASN1::encodeDER(ASN1::INTEGER_TYPE, chr(0))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['n'])))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, Util::base64url_decode($this->data['e']))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['d'])))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['p'])))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['q'])))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['dp'])))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['dq'])))
                . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['qi']))),
            false);

            return wordwrap("-----BEGIN RSA PRIVATE KEY-----\n" . base64_encode($der) . "\n-----END RSA PRIVATE KEY-----\n", 64, "\n", true);
        }
    }

    protected function getThumbnailMembers() {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['e', 'kty', 'n'];
    }
}

?>
