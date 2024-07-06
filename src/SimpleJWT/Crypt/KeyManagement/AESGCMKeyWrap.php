<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2023-2024
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
use SimpleJWT\Crypt\Encryption\AESGCM;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Util\Util;

/**
 * Implements AES GCM key encryption algorithm.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.7
 */
class AESGCMKeyWrap extends BaseAlgorithm implements KeyEncryptionAlgorithm {
    /** @var AESGCM $aesgcm */
    private $aesgcm;

    public function __construct(?string $alg) {
        $this->aesgcm = new AESGCM(($alg == null) ? null : substr($alg, 0, -2));
        parent::__construct($alg);
    }

    public function getSupportedAlgs(): array {
        $aesgcm_algs = $this->aesgcm->getSupportedAlgs();
        return array_map(function ($alg) { return $alg . 'KW'; }, $aesgcm_algs);
    }

    public function getKeyCriteria(): array {
        return [
            'kty' => 'oct',
            '~alg' => $this->getAlg(),
            '@use' => 'enc',
            '@key_ops' => ['wrapKey', 'unwrapKey']
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function encryptKey(string $cek, KeySet $keys, array &$headers, ?string $kid = null): string {
        /** @var SymmetricKey $key */
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        $iv = Util::base64url_encode($this->generateIV());
        $results = $this->aesgcm->encryptAndSign($cek, $key->toBinary(), '', $iv);
        $headers['iv'] = $iv;
        $headers['tag'] = $results['tag'];
        return $results['ciphertext'];
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
        if (!isset($headers['iv']) || !isset($headers['tag'])) {
            throw new CryptException('iv or tag headers not set');
        }

        $cek = $this->aesgcm->decryptAndVerify($encrypted_key, $headers['tag'], $key->toBinary(), '', $headers['iv']);

        return $cek;
    }

    /**
     * Generates the initialisation vector.  This uses
     * {@link SimpleJWT\Util\Util::random_bytes()} to generate random bytes.
     *
     * @return string the initialisation vector as a binary string
     */
    protected function generateIV(): string {
        /** @var int<1, max> $len */
        $len = intval($this->aesgcm->getIVSize() / 8);
        return Util::random_bytes($len);
    }
}
?>
