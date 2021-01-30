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

namespace SimpleJWT\Crypt;

use SimpleJWT\Keys\Key;
use SimpleJWT\Keys\KeyException;
use SimpleJWT\Util\ASN1;
use SimpleJWT\Util\Util;

/**
 * SHA2 signature algorithms that use the OpenSSL library.  These include
 * RSA-SHA and EC-SHA algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`,
 * `ES512` and `ES256K`.
 */
class OpenSSLSig extends SHA2 {
    private $family;

    public function __construct($alg) {
        if ($alg == null) {
            parent::__construct(null, null);
        } else {
            parent::__construct($alg, filter_var($alg, FILTER_SANITIZE_NUMBER_INT));
            $this->family = substr($alg, 0, 2);
        }
    }

    public function getKeyCriteria() {
        switch ($this->family) {
            case 'RS':
                return ['kty' => 'RSA', '@use' => 'sig', '@key_ops' => ['sign', 'verify']];
            case 'ES':
                return ['kty' => 'EC', '@use' => 'sig', '@key_ops' => ['sign', 'verify']];
        }
    }

    public function getSupportedAlgs() {
        $results = [];
        $hashes = [];

        $hash_algos = array_map('strtoupper', openssl_get_md_methods());
        if (in_array('SHA256', $hash_algos)) $hashes[] = 256;
        if (in_array('SHA384', $hash_algos)) $hashes[] = 384;
        if (in_array('SHA512', $hash_algos)) $hashes[] = 512;

        if (defined('OPENSSL_KEYTYPE_RSA')) {
            foreach ($hashes as $size) $results[] = 'RS' . $size;
        }
        if (defined('OPENSSL_KEYTYPE_EC')) {
            foreach ($hashes as $size) $results[] = 'ES' . $size;

            if (function_exists('openssl_get_curve_names') && in_array('secp256k1', openssl_get_curve_names()) && in_array('SHA256', $hash_algos))
                $results[] = 'ES256K';
        }

        return $results;
    }

    public function sign($data, $keys, $kid = null) {
        $key = $this->getSigningKey($keys, $kid);
        if ($key == null) {
            throw new KeyException('Key not found or is invalid');
        }

        $binary = '';
        if (!openssl_sign($data, $binary, $key->toPEM(), 'SHA' . $this->size)) {
            $messages = [];
            while ($message = openssl_error_string()) $messages[] = $message;
            throw new CryptException('Cannot calculate signature: ' . implode("\n", $messages));
        }

        if ($key->getKeyType() == \SimpleJWT\Keys\ECKey::KTY) {
            // OpenSSL returns ECDSA signatures as an ASN.1 DER SEQUENCE
            $offset = 0;
            $offset += ASN1::readDER($binary, $offset, $value);  // SEQUENCE
            $offset += ASN1::readDER($binary, $offset, $r);  // INTEGER
            $offset += ASN1::readDER($binary, $offset, $s);  // INTEGER

            // DER integers are big-endian in two's complement form. We need to
            // convert these to unsigned integers.  But the r and s values are always
            // positive, so it is just a matter of stripping out the leading null
            $r = ltrim($r, "\x00");
            $s = ltrim($s, "\x00");

            // Now pad out r and s so that they are $key->getSize() bits long
            $r = str_pad($r, $key->getSize() / 8, "\x00", STR_PAD_LEFT);
            $s = str_pad($s, $key->getSize() / 8, "\x00", STR_PAD_LEFT);

            $binary = $r . $s;
        }

        return Util::base64url_encode($binary);
    }

    public function verify($signature, $data, $keys, $kid = null) {
        $key = $this->selectKey($keys, $kid, [Key::PUBLIC_PROPERTY => true, '~use' => 'sig']);
        if ($key == null) {
            throw new KeyException('Key not found or is invalid');
        }

        $binary = Util::base64url_decode($signature);

        if ($key->getKeyType() == \SimpleJWT\Keys\ECKey::KTY) {
            // For ECDSA signatures, OpenSSL expects a ASN.1 DER SEQUENCE
            list($r, $s) = str_split($binary, (int) (strlen($binary) / 2));

            // Trim leading zeros
            $r = ltrim($r, "\x00");
            $s = ltrim($s, "\x00");

            // Convert r and s from unsigned big-endian integers to signed two's complement
            if (ord($r[0]) > 0x7f) $r = "\x00" . $r;
            if (ord($s[0]) > 0x7f) $s = "\x00" . $s;

            $binary = ASN1::encodeDER(ASN1::SEQUENCE,
                ASN1::encodeDER(ASN1::INTEGER_TYPE, $r) .
                ASN1::encodeDER(ASN1::INTEGER_TYPE, $s),
            false);
        }

        $result = openssl_verify($data, $binary, $key->toPEM(), 'SHA' . $this->size);

        switch ($result) {
            case 1:
                return true;
                break;
            case 0:
                return false;
                break;
            default:
                $messages = [];
                while ($message = openssl_error_string()) $messages[] = $message;
                throw new CryptException('Cannot verify signature: ' . implode("\n", $messages));
                return false;
                break;
        }
    }

    public function getSigningKey($keys, $kid = null) {
        return $this->selectKey($keys, $kid, [Key::PUBLIC_PROPERTY => false]);
    }
}

?>
