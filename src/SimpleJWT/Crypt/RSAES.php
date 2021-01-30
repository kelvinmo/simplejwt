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

use SimpleJWT\Util\Util;
use SimpleJWT\Keys\Key;

/**
 * Implementation of the RSA Encryption Scheme algorithms, including `RSA1_5` and
 * the RSAES with Optimal Asymmetric Encryption Padding (OAEP).
 * 
 * @see https://tools.ietf.org/html/rfc7518#section-4.2
 * @see https://tools.ietf.org/html/rfc7518#section-4.3
 * @see https://tools.ietf.org/html/rfc3447
 */
class RSAES extends Algorithm implements KeyEncryptionAlgorithm {
    static protected $alg_params = [
        'RSA1_5' => ['padding' => OPENSSL_PKCS1_PADDING],
        'RSA-OAEP' => ['padding' => OPENSSL_PKCS1_OAEP_PADDING],
        'RSA-OAEP-256' => ['padding' => OPENSSL_NO_PADDING, 'oaep' => 'sha256']
    ];


    public function __construct($alg) {
        parent::__construct($alg);
    }

    public function getSupportedAlgs() {
        return array_keys(self::$alg_params);
    }

    public function getKeyCriteria() {
        return [
            'kty' => 'RSA',
            '@use' => 'enc',
            '@key_ops' => ['wrapKey', 'unwrapKey']
        ];
    }

    /**
     * Generates a seed for OAEP encoding.  This uses {@link SimpleJWT\Util\Util::random_bytes()}
     * to generate random bytes.
     *
     * @param int $len the length of the seed required, in octets
     * @return string the seed
     */
    protected function generateSeed($len) {
        return Util::random_bytes($len);
    }

    public function encryptKey($cek, $keys, &$headers, $kid = null) {
        $key = $this->selectKey($keys, $kid, [Key::PUBLIC_PROPERTY => true]);
        if (($key == null) || !$key->isPublic()) {
            throw new CryptException('Key not found or is invalid');
        }
        $headers['kid'] = $key->getKeyId();

        $params = self::$alg_params[$this->getAlg()];

        if (isset($params['oaep'])) {
            // $key->getSize() ignores the first octet when calculating the key size,
            // therefore we need to add it back in
            $cek = $this->oaep_encode($cek, 1 + $key->getSize() / 8, $params['oaep']);
        }

        $ciphertext = '';
        if (!openssl_public_encrypt($cek, $ciphertext, $key->toPEM(), $params['padding'])) {
            $messages = [];
            while ($message = openssl_error_string()) $messages[] = $message;
            throw new CryptException('Cannot encrypt key: ' . implode("\n", $messages));
        }

        return Util::base64url_encode($ciphertext);
    }

    public function decryptKey($encrypted_key, $keys, $headers, $kid = null) {
        $key = $this->selectKey($keys, $kid, [Key::PUBLIC_PROPERTY => false]);
        if (($key == null) || $key->isPublic()) {
            throw new CryptException('Key not found or is invalid');
        }

        $params = self::$alg_params[$this->getAlg()];

        $cek = '';
        if (!openssl_private_decrypt(Util::base64url_decode($encrypted_key), $cek, $key->toPEM(), $params['padding'])) {
            $messages = [];
            while ($message = openssl_error_string()) $messages[] = $message;
            throw new CryptException('Cannot decrypt key: ' . implode("\n", $messages));
        }

        if (isset($params['oaep'])) {
            // $key->getSize() ignores the first octet when calculating the key size,
            // therefore we need to add it back in
            $cek = $this->oaep_decode($cek, 1 + $key->getSize() / 8, $params['oaep']);
        }

        return $cek;
    }

    /**
     * Encodes a message using EME-OAEP.
     *
     * @param string $message the message to encode
     * @param int $key_length the length of the RSA key in octets
     * @param string $hash the hash algorithm - must be one supported by `hash_algos()`
     * @param string $label the label
     * @return string the encoded message
     * @see https://tools.ietf.org/html/rfc3447
     */
    final protected function oaep_encode($message, $key_length, $hash = 'sha1', $label = '') {
        $lHash = hash($hash, $label, true);
        $PS = str_repeat("\x00", $key_length - strlen($message) - 2 * strlen($lHash) - 2);
        $DB = $lHash . $PS . "\x01" . $message;
        $seed = $this->generateSeed(strlen($lHash));
        $dbMask = $this->mgf1($seed, $key_length - strlen($lHash) - 1, $hash);
        $maskedDB = $DB ^ $dbMask;
        $seedMask = $this->mgf1($maskedDB, strlen($seed), $hash);
        $maskedSeed = $seed ^ $seedMask;
        return "\x00" . $maskedSeed . $maskedDB;
    }

    /**
     * Decodes a message using EME-OAEP.
     *
     * @param string $message the message to decode
     * @param int $key_length the length of the RSA key in octets
     * @param string $hash the hash algorithm - must be one supported by `hash_algos()`
     * @param string $label the label
     * @return string the decoded message
     * @throws CryptException if an error occurred in the decoding
     * @see https://tools.ietf.org/html/rfc3447
     */
    final protected function oaep_decode($encoded, $key_length, $hash = 'sha1', $label = '') {
        $lHash = hash($hash, $label, true);

        $Y = ord($encoded[0]);
        $maskedSeed = substr($encoded, 1, strlen($lHash));
        $maskedDB = substr($encoded, strlen($lHash) + 1);
        $seedMask = $this->mgf1($maskedDB, strlen($lHash), $hash);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = $this->mgf1($seed, $key_length - strlen($lHash) - 1, $hash);
        $DB = $maskedDB ^ $dbMask;

        $lHash2 = substr($DB, 0, strlen($lHash));
        if (!Util::secure_compare($lHash, $lHash2)) {
            throw new CryptException('OAEP decoding error');
        }
        $PSM = substr($DB, strlen($lHash));
        $PSM = ltrim($PSM, "\x00");
        if (substr($PSM, 0, 1) != "\x01") {
            throw new CryptException('OAEP decoding error');
        }
        return substr($PSM, 1);
    }

    /**
     * Generate a mask using the MGF1 algorithm and a specified hash algorithm.
     *
     * @param string $seed the seed
     * @param int $l the desired length of the mask in octets
     * @param string $hash the hash function
     * @return string the mask
     * @see https://tools.ietf.org/html/rfc3447#appendix-B.2.1
     */
    final protected function mgf1($seed, $l, $hash = 'sha1') {
        $hlen = strlen(hash($hash, '', true));
        $T = '';
        $count = ceil($l / $hlen);
        for ($i = 0; $i < $count; $i++) {
            $C = pack('N', $i);
            $T .= hash($hash, $seed . $C, true);
        }

        return substr($T, 0, $l);
    }
}
