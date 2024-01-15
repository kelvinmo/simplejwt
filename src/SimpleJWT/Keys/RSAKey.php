<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2024
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
use SimpleJWT\Util\Util;

/**
 * A class representing a public or private key in an RSA key pair.
 */
class RSAKey extends Key implements PEMInterface {

    const KTY = 'RSA';
    const COSE_KTY = 3;

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
                $this->replaceDataKeys([ -1 => 'n', -2 => 'e', -3 => 'd', -4 => 'p', -5 => 'q', -6 => 'dp', -7 => 'dq', -8 => 'qi' ]);
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
                    if ($algorithm != self::OID) throw new KeyException('Not RSA key');

                    $public_bitstring = $seq->getChildAt(1)->getValue();
                    $public_seq = $der->decode($public_bitstring);

                    $jwk['kty'] = self::KTY;
                    $jwk['n'] = Util::base64url_encode($public_seq->getChildAt(0)->getValueAsUIntOctets());
                    $jwk['e'] = Util::base64url_encode($public_seq->getChildAt(1)->getValueAsUIntOctets());
                } elseif (preg_match(self::PEM_PRIVATE, $data, $matches)) {
                    /** @var string $binary */
                    $binary = base64_decode($matches[1]);
                    if ($binary == FALSE) throw new KeyException('Cannot read PEM key');

                    $seq = $der->decode($binary);

                    $version = $seq->getChildAt(0)->getValue();
                    if ($version != 0) throw new KeyException('Unsupported RSA private key version');

                    $jwk['kty'] = self::KTY;
                    $jwk['n'] = Util::base64url_encode($seq->getChildAt(1)->getValueAsUIntOctets());
                    $jwk['e'] = Util::base64url_encode($seq->getChildAt(2)->getValueAsUIntOctets());
                    $jwk['d'] = Util::base64url_encode($seq->getChildAt(3)->getValueAsUIntOctets());
                    $jwk['p'] = Util::base64url_encode($seq->getChildAt(4)->getValueAsUIntOctets());
                    $jwk['q'] = Util::base64url_encode($seq->getChildAt(5)->getValueAsUIntOctets());
                    $jwk['dp'] = Util::base64url_encode($seq->getChildAt(6)->getValueAsUIntOctets());
                    $jwk['dq'] = Util::base64url_encode($seq->getChildAt(7)->getValueAsUIntOctets());
                    $jwk['qi'] = Util::base64url_encode($seq->getChildAt(8)->getValueAsUIntOctets());
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
        // The modulus is a signed integer, therefore ignore the first byte
        return 8 * (strlen(Util::base64url_decode($this->data['n'])) - 1);
    }

    public function isPublic(): bool {
        return !isset($this->data['p']);
    }

    public function getPublicKey(): RSAKey {
        $data = [
            'kty' => $this->data['kty'],
            'n' => $this->data['n'],
            'e' => $this->data['e']
        ];
        if (isset($this->data['kid'])) $data['kid'] = $this->data['kid'];
        return new RSAKey($data, 'php');
    }

    public function toPEM(): string {
        $der = new DER();

        if ($this->isPublic()) {
            $public_seq = ASN1Value::sequence([
                ASN1Value::integer(Util::base64url_decode($this->data['n'])),
                ASN1Value::integer(Util::base64url_decode($this->data['e']))
            ]);
            $public_bitstring = $der->encode($public_seq);

            $seq = ASN1Value::sequence([
                ASN1Value::sequence([
                    ASN1Value::oid(self::OID),
                    ASN1Value::null()
                ]),
                ASN1Value::bitString($public_bitstring)
            ]);
            $binary = $der->encode($seq);

            return wordwrap("-----BEGIN PUBLIC KEY-----\n" . base64_encode($binary) . "\n-----END PUBLIC KEY-----\n", 64, "\n", true);
        } else {
            $seq = ASN1Value::sequence([
                ASN1Value::integer(0),
                ASN1Value::integer(Util::base64url_decode($this->data['n'])),
                ASN1Value::integer(Util::base64url_decode($this->data['e'])),
                ASN1Value::integer(Util::base64url_decode($this->data['d'])),
                ASN1Value::integer(Util::base64url_decode($this->data['p'])),
                ASN1Value::integer(Util::base64url_decode($this->data['q'])),
                ASN1Value::integer(Util::base64url_decode($this->data['dp'])),
                ASN1Value::integer(Util::base64url_decode($this->data['dq'])),
                ASN1Value::integer(Util::base64url_decode($this->data['qi']))
            ]);
            $binary = $der->encode($seq);

            return wordwrap("-----BEGIN RSA PRIVATE KEY-----\n" . base64_encode($binary) . "\n-----END RSA PRIVATE KEY-----\n", 64, "\n", true);
        }
    }

    protected function getThumbnailMembers(): array {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['e', 'kty', 'n'];
    }
}

?>
