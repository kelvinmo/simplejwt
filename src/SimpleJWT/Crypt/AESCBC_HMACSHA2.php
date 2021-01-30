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

/**
 * Implementation of the AES_CBC_HMAC_SHA2 family of algorithms.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.2
 */
class AESCBC_HMACSHA2 extends Algorithm implements EncryptionAlgorithm {

    static protected $alg_params = [
        'A128CBC-HS256' => ['cipher' => 'AES-128-CBC', 'hash' => 'sha256', 'key' => 32, 'tag' => 16],
        'A192CBC-HS384' => ['cipher' => 'AES-192-CBC', 'hash' => 'sha384', 'key' => 48, 'tag' => 24],
        'A256CBC-HS512' => ['cipher' => 'AES-256-CBC', 'hash' => 'sha512', 'key' => 64, 'tag' => 32],
    ];

    public function __construct($alg) {
        parent::__construct($alg);
    }

    public function getSupportedAlgs() {
        $ciphers = array_map('strtoupper', openssl_get_cipher_methods());
        $hashes = hash_algos();
        $results = [];

        foreach (self::$alg_params as $alg => $param) {
            if (in_array($param['cipher'], $ciphers) && in_array($param['hash'], $hashes)) {
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

        list($mac_key, $enc_key) = str_split($cek, (int) (strlen($cek) / 2));
        $al = Util::packInt64(strlen($additional) * 8);

        $e = openssl_encrypt($plaintext, $params['cipher'], $enc_key, OPENSSL_RAW_DATA, $iv);
        $m = hash_hmac($params['hash'], $additional . $iv . $e . $al, $mac_key, true);
        $t = substr($m, 0, $params['tag']);

        return [
            'ciphertext' => Util::base64url_encode($e),
            'tag' => Util::base64url_encode($t),
            'iv' => Util::base64url_encode($iv),
        ];
    }

    // check cek and iv formats
    public function decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv) {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) throw new CryptException('Incorrect key length');

        $iv = Util::base64url_decode($iv);
        if (strlen($iv) != $this->getIVSize() / 8) throw new CryptException('Incorrect IV length');

        list($mac_key, $enc_key) = str_split($cek, (int) (strlen($cek) / 2));
        $al = Util::packInt64(strlen($additional) * 8);

        $e = Util::base64url_decode($ciphertext);
        $m = hash_hmac($params['hash'], $additional . $iv . $e . $al, $mac_key, true);
        $t = substr($m, 0, $params['tag']);

        if (!Util::secure_compare(Util::base64url_decode($tag), $t)) throw new CryptException('Authentication tag does not match');
        
        $plaintext = openssl_decrypt($e, $params['cipher'], $enc_key, OPENSSL_RAW_DATA, $iv);

        return $plaintext;
    }

    public function getCEKSize() {
        return 8 * self::$alg_params[$this->getAlg()]['key'];
    }

    public function getIVSize() {
        return 128;
    }
}

?>
