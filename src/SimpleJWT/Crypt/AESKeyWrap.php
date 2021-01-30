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
 * Implementation of the AES Key Wrap algorithms.
 * 
 * @see https://tools.ietf.org/html/rfc7518#section-4.4
 * @see https://tools.ietf.org/html/rfc3394
 */
class AESKeyWrap extends Algorithm implements KeyEncryptionAlgorithm {

    const RFC3394_IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    static protected $alg_params = [
        'A128KW' => ['cipher' => 'AES-128-ECB', 'key' => 16],
        'A192KW' => ['cipher' => 'AES-192-ECB', 'key' => 24],
        'A256KW' => ['cipher' => 'AES-256-ECB', 'key' => 32],
    ];

    public function __construct($alg) {
        parent::__construct($alg);
    }

    public function getSupportedAlgs() {
        $ciphers = array_map('strtoupper', openssl_get_cipher_methods());
        $results = [];

        foreach (self::$alg_params as $alg => $param) {
            if (in_array($param['cipher'], $ciphers)) {
                $results[] = $alg;
            }
        }

        return $results;
    }

    public function getKeyCriteria() {
        $alg = $this->getAlg();
        $size = self::$alg_params[$alg]['key'] * 8;
        return [
            'kty' => 'oct',
            Key::SIZE_PROPERTY => $size,
            '~alg' => $this->getAlg(),
            '@use' => 'enc',
            '@key_ops' => ['wrapKey', 'unwrapKey']
        ];
    }

    public function encryptKey($cek, $keys, &$headers, $kid = null) {
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        if ((strlen($cek) % 8) != 0) throw new CryptException('Content encryption key not a multiple of 64 bits');

        $cipher = self::$alg_params[$this->getAlg()]['cipher'];

        $A = self::RFC3394_IV;
        $P = str_split($cek, 8);
        $R = str_split($cek, 8);
        $n = count($P);

        for ($j = 0; $j <= 5; $j++) {
            for ($i = 0; $i < $n; $i++) {
                $t = $n * $j + ($i + 1);
                $B = openssl_encrypt($A . $R[$i], $cipher, $key->toBinary(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                $A = $this->msb($B) ^ Util::packInt64($t);
                $R[$i] = $this->lsb($B);
            }
        }

        return Util::base64url_encode($A . implode('', $R));
    }

    public function decryptKey($encrypted_key, $keys, $headers, $kid = null) {
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        $cipher = self::$alg_params[$this->getAlg()]['cipher'];

        $R = str_split(Util::base64url_decode($encrypted_key), 8);
        $A = array_shift($R);
        $n = count($R);

        for ($j = 5; $j >= 0; $j--) {
            for ($i = $n - 1; $i >= 0; $i--) {
                $t = $n * $j + ($i + 1);
                $B = openssl_decrypt(($A ^ Util::packInt64($t)) . $R[$i], $cipher, $key->toBinary(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                $A = $this->msb($B);
                $R[$i] = $this->lsb($B);
            }
        }

        if (!Util::secure_compare($A, self::RFC3394_IV)) {
            throw new CryptException('AES key wrap integrity check failed');
        }

        return implode('', $R);
    }

    /**
     * Returns the most significant half of a specified value
     *
     * @param string $x the value
     * @return string the most significant half
     */
    protected function msb($x) {
        return substr($x, 0, strlen($x) / 2);
    }

    /**
     * Returns the least significant half of a specified value
     *
     * @param string $x the value
     * @return string the least significant half
     */
    protected function lsb($x) {
        return substr($x, strlen($x) / 2);
    }

}

?>
