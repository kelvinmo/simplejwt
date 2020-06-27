<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2020
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

use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;

/**
 * Abstract class for the AES Key Wrap encryption algorithm, where the key to be wrapped
 * is derived from a key derivation algorithm.
 * 
 * This is a convenience class for algorithms implementing the `x+AyyyKW` family of
 * algorithms.  Subclasses can call methods in this class for the AES Key Wrap functions.
 */
abstract class AESWrappedKeyAlgorithm extends Algorithm implements KeyEncryptionAlgorithm {
    /** @var AESKeyWrap the underlying AES key wrap algorithm */
    private $aeskw;

    public function __construct($alg) {
        parent::__construct($alg);

        if ($alg == null) {
            $this->aeskw = new AESKeyWrap(null);
        } else {
            list($dummy, $aeskw_alg) = explode('+', $alg, 2);
            $this->aeskw = new AESKeyWrap($aeskw_alg);
        }
    }

    /**
     * Returns the supported AES Key Wrap algorithms
     * 
     * @return array an array of AES Key Wrap algorithms
     */
    protected function getAESKWAlgs() {
        return $this->aeskw->getSupportedAlgs();
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
     * Wraps a key using the AES Key Wrap algorithm
     * 
     * @param string $plain_key the key to wrap as a binary string
     * @param string $wrapping_key the key wrapping key as a binary string
     * @param array &$headers the JWE header, which can be modified
     * @return string the wrapped key as a binary string
     */
    protected function wrapKey($plain_key, $wrapping_key, &$headers) {
        $keys = $this->createKeySet($wrapping_key);
        return $this->aeskw->encryptKey($plain_key, $keys, $headers);
    }

    /**
     * Unwraps a key using the AES Key Wrap algorithm
     * 
     * @param string $encrypted_key the key to unwrap as a binary string
     * @param string $unwrapping_key the key wrapping key as a binary string
     * @param array $headers the JWE header, which can be modified
     * @return string the unwrapped key as a binary string
     */
    protected function unwrapKey($encrypted_key, $unwrapping_key, $headers) {
        $keys = $this->createKeySet($unwrapping_key);
        return $this->aeskw->decryptKey($encrypted_key, $keys, $headers);
    }

    private function createKeySet($key) {
        $keys = new KeySet();
        $keys->add(new SymmetricKey($key, 'bin'));
        return $keys;
    }
}

?>