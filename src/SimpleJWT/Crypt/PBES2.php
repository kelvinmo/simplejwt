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
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;

/**
 * Implements PBES2 key encryption algorithm with AES key wrap.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.8
 */
class PBES2 extends Algorithm implements KeyEncryptionAlgorithm {

    static protected $alg_params = [
        'PBES2-HS256+A128KW' => ['hash' => 'sha256'],
        'PBES2-HS384+A192KW' => ['hash' => 'sha384'],
        'PBES2-HS512+A256KW' => ['hash' => 'sha512']
    ];

    protected $hash_alg;
    protected $aeskw;

    protected $iterations = 4096;

    public function __construct($alg) {
        parent::__construct($alg);

        if ($alg != null) {
            list ($dummy, $aeskw_alg) = explode('+', $alg, 2);
            $this->hash_alg = self::$alg_params[$alg]['hash'];
            $this->aeskw = new AESKeyWrap($aeskw_alg);
        }
    }

    public function getSupportedAlgs() {
        $results = [];

        $aeskw = new AESKeyWrap(null);
        $aeskw_algs = $aeskw->getSupportedAlgs();
        $hash_algs = hash_algos();

        foreach (self::$alg_params as $alg => $params) {
            list ($dummy, $aeskw_alg) = explode('+', $alg, 2);
            if (in_array($params['hash'], $hash_algs) && in_array($aeskw_alg, $aeskw_algs)) {
                $results[] = $alg;
            }
        }

        return $results;
    }

    public function getKeyCriteria() {
        $alg = $this->getAlg();
        return [
            'kty' => 'oct',
            '~alg' => $this->getAlg(),
            '@use' => 'enc',
            '@key_ops' => ['wrapKey', 'unwrapKey']
        ];
    }

    /**
     * Sets the number of iterations to use in PBKFD2 key generation.
     *
     * @param int $iterations number of iterations
     */
    public function setIterations($iterations) {
        $this->iterations = $iterations;
    }

    public function encryptKey($cek, $keys, &$headers, $kid = null) {
        $salt_input = $this->generateSaltInput();
        $headers['p2s'] = Util::base64url_encode($salt_input);
        $headers['p2c'] = $this->iterations;

        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        $derived_keyset = $this->getKeySetFromPassword($key->toBinary(), $headers);
        return $this->aeskw->encryptKey($cek, $derived_keyset, $headers);
    }

    public function decryptKey($encrypted_key, $keys, $headers, $kid = null) {
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        $derived_keyset = $this->getKeySetFromPassword($key->toBinary(), $headers);
        return $this->aeskw->decryptKey($encrypted_key, $derived_keyset, $headers);
    }

    /**
     * Returns the required key size for the AES key wrap key
     *
     * @return int the key size, in bits
     */
    protected function getAESKWKeySize() {
        $criteria = $this->aeskw->getKeyCriteria();
        return $criteria[Key::SIZE_PROPERTY];
    }

    /**
     * Generates salt input.  This uses {@link SimpleJWT\Util\Util::random_bytes()}
     * to generate random bytes.
     *
     * @return string the salt input
     */
    protected function generateSaltInput() {
        return Util::random_bytes(8);
    }

    private function getKeySetFromPassword($password, $headers) {
        $salt = $headers['alg'] . "\x00" . Util::base64url_decode($headers['p2s']);

        $hash = hash_pbkdf2($this->hash_alg, $password, $salt, $headers['p2c'], $this->getAESKWKeySize() / 8, true);
        $keys = new KeySet();
        $keys->add(new SymmetricKey($hash, 'bin'));
        return $keys;
    }
}

if (!function_exists('hash_pbkdf2') && function_exists('hash_hmac')) {
    function hash_pbkdf2($algo, $password, $salt, $iterations, $length = 0, $raw_output = false) {
        $result = '';
        $hLen = strlen(hash($algo, '', true));
        if ($length == 0) {
            $length = $hLen;
            if (!$raw_output) $length *= 2;
        }
        $l = ceil($length / $hLen);

        for ($i = 1; $i <= $l; $i++) {
            $U = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $T = $U;
            for ($j = 1; $j < $iterations; $j++) {
                $T ^= ($U = hash_hmac($algo, $U, $password, true));
            }
            $result .= $T;
        }

        return substr(($raw_output) ? $result : bin2hex($result), 0, $length);
    }
}
?>
