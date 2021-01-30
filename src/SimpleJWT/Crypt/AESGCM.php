<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2020-2021
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

/**
 * Implementation of the AES GCM family of algorithms.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.3
 */
class AESGCM extends Algorithm implements EncryptionAlgorithm {

    static protected $alg_params = [
        'A128GCM' => ['cipher' => 'aes-128-gcm', 'key' => 16],
        'A192GCM' => ['cipher' => 'aes-192-gcm', 'key' => 24],
        'A256GCM' => ['cipher' => 'aes-256-gcm', 'key' => 32],
    ];

    public function __construct($alg) {
        parent::__construct($alg);
    }

    public function getSupportedAlgs() {
        if (!version_compare(PHP_VERSION, '7.1', '>=')) return [];

        $ciphers = array_map('strtolower', openssl_get_cipher_methods());
        $results = [];

        foreach (self::$alg_params as $alg => $param) {
            if (in_array($param['cipher'], $ciphers)) {
                $results[] = $alg;
            }
        }

        return $results;
    }

    public function getKeyCriteria() {
        return ['kty' => 'oct', '@use' => 'enc', '@key_ops' => ['encrypt', 'decrypt']];
    }

    // cek binary iv base64url
    public function encryptAndSign($plaintext, $cek, $additional, $iv = null) {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) throw new CryptException('Incorrect key length');

        if ($iv == null) {
            $iv = openssl_random_pseudo_bytes($this->getIVSize() / 8);
        } else {
            $iv = Util::base64url_decode($iv);
            if (strlen($iv) != $this->getIVSize() / 8) throw new CryptException('Incorrect IV length');
        }

        $e = openssl_encrypt($plaintext, $params['cipher'], $cek, OPENSSL_RAW_DATA, $iv, $tag, $additional, 16);

        return [
            'ciphertext' => Util::base64url_encode($e),
            'tag' => Util::base64url_encode($tag),
            'iv' => Util::base64url_encode($iv),
        ];
    }

    // check cek and iv formats
    public function decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv) {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) throw new CryptException('Incorrect key length');

        $iv = Util::base64url_decode($iv);
        if (strlen($iv) != $this->getIVSize() / 8) throw new CryptException('Incorrect IV length');

        $tag = Util::base64url_decode($tag);
        if (strlen($tag) != 16) throw new CryptException('Incorrect authentication tag length');
        
        $plaintext = openssl_decrypt(Util::base64url_decode($ciphertext), $params['cipher'], $cek, OPENSSL_RAW_DATA, $iv, $tag, $additional);
        if ($plaintext === false) throw new CryptException('Authentication tag does not match');

        return $plaintext;
    }

    public function getCEKSize() {
        return 8 * self::$alg_params[$this->getAlg()]['key'];
    }

    public function getIVSize() {
        return 96;
    }
}

?>
