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

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Keys\Key;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Util\Util;

/**
 * Implements PBES2 key encryption algorithm with AES key wrap.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.8
 */
class PBES2 extends BaseAlgorithm implements KeyEncryptionAlgorithm {
    use AESKeyWrapTrait;

    /** @var array<string, mixed> $alg_params */
    static protected $alg_params = [
        'PBES2-HS256+A128KW' => ['hash' => 'sha256'],
        'PBES2-HS384+A192KW' => ['hash' => 'sha384'],
        'PBES2-HS512+A256KW' => ['hash' => 'sha512']
    ];

    /** @var truthy-string $hash_alg */
    protected $hash_alg;

    /** @var int $iterations */
    protected $iterations = 4096;

    public function __construct(?string $alg) {
        if ($alg != null) {
            $this->hash_alg = self::$alg_params[$alg]['hash'];

            list($pbes2_alg, $aeskw_alg) = explode('+', $alg, 2);
            $this->initAESKW($aeskw_alg);
        } else {
            $this->initAESKW();
        }
        
        parent::__construct($alg);
    }

    public function getSupportedAlgs(): array {
        $results = [];

        $aeskw_algs = $this->getAESKWAlgs();
        $hash_algs = hash_algos();

        foreach (self::$alg_params as $alg => $params) {
            list ($dummy, $aeskw_alg) = explode('+', $alg, 2);
            if (in_array($params['hash'], $hash_algs) && in_array($aeskw_alg, $aeskw_algs)) {
                $results[] = $alg;
            }
        }

        return $results;
    }

    public function getKeyCriteria(): array {
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
     * @return void
     */
    public function setIterations(int $iterations) {
        $this->iterations = $iterations;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptKey(string $cek, KeySet $keys, array &$headers, ?string $kid = null): string {
        $salt_input = $this->generateSaltInput();
        $headers['p2s'] = Util::base64url_encode($salt_input);
        $headers['p2c'] = $this->iterations;

        /** @var SymmetricKey $key */
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        $derived_key = $this->generateKeyFromPassword($key->toBinary(), $headers);
        return $this->wrapKey($cek, $derived_key, $headers);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptKey(string $encrypted_key, KeySet $keys, array $headers, ?string $kid = null): string {
        /** @var SymmetricKey $key */
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }
        if (!isset($headers['p2s']) || !isset($headers['p2c'])) {
            throw new CryptException('p2s or p2c headers not set');
        }

        $derived_key = $this->generateKeyFromPassword($key->toBinary(), $headers);
        return $this->unwrapKey($encrypted_key, $derived_key, $headers);
    }

    /**
     * Generates salt input.  This uses {@link SimpleJWT\Util\Util::random_bytes()}
     * to generate random bytes.
     *
     * @return string the salt input
     */
    protected function generateSaltInput(): string {
        return Util::random_bytes(8);
    }

    /**
     * @param array<string, mixed> $headers
     */
    private function generateKeyFromPassword(string $password, array $headers): string {
        $salt = $headers['alg'] . "\x00" . Util::base64url_decode($headers['p2s']);
        /** @var int<0, max> $length */
        $length = intdiv($this->getAESKWKeySize(), 8);

        return hash_pbkdf2($this->hash_alg, $password, $salt, $headers['p2c'], $length, true);
    }
}
?>
