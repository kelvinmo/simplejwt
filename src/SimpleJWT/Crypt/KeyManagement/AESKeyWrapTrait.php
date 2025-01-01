<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2020-2025
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

use SimpleJWT\Keys\KeyInterface;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;

/**
 * Trait for implementing the AES Key Wrap encryption algorithm, where the key to be wrapped
 * is derived from a key derivation algorithm.
 * 
 * This is a convenience class for algorithms implementing the `x+AyyyKW` family of
 * algorithms.  Subclasses can call methods in this class for the AES Key Wrap functions.
 */
trait AESKeyWrapTrait {
    /** @var AESKeyWrap the underlying AES key wrap algorithm */
    private $aeskw;

    /**
     * Initialises the underlying AES key wrap algorithm.  This method
     * must be called from the constructor.
     * 
     * @param string $alg the AES key wrap algorithm parameter
     * @return void
     */
    protected function initAESKW(?string $alg = null) {
        if ($alg == null) {
            $this->aeskw = new AESKeyWrap(null);
        } else {
            $this->aeskw = new AESKeyWrap($alg);
        }
    }

    /**
     * Returns the supported AES Key Wrap algorithms
     * 
     * @return array<string> an array of AES Key Wrap algorithms
     */
    protected function getAESKWAlgs(): array {
        return $this->aeskw->getSupportedAlgs();
    }

    /**
     * Returns the required key size for the AES key wrap key
     *
     * @return int the key size, in bits
     */
    protected function getAESKWKeySize(): int {
        $criteria = $this->aeskw->getKeyCriteria();
        return $criteria[KeyInterface::SIZE_PROPERTY];
    }

    /**
     * Wraps a key using the AES Key Wrap algorithm
     * 
     * @param string $plain_key the key to wrap as a binary string
     * @param string $wrapping_key the key wrapping key as a binary string
     * @param array<string, mixed> &$headers the JWE header, which can be modified
     * @return string the wrapped key as a binary string
     */
    protected function wrapKey(string $plain_key, string $wrapping_key, array &$headers): string {
        $keys = $this->createKeySet($wrapping_key);
        return $this->aeskw->encryptKey($plain_key, $keys, $headers);
    }

    /**
     * Unwraps a key using the AES Key Wrap algorithm
     * 
     * @param string $encrypted_key the key to unwrap as a binary string
     * @param string $unwrapping_key the key wrapping key as a binary string
     * @param array<string, mixed> $headers the JWE header, which can be modified
     * @return string the unwrapped key as a binary string
     */
    protected function unwrapKey(string $encrypted_key, string $unwrapping_key, array $headers): string {
        $keys = $this->createKeySet($unwrapping_key);
        return $this->aeskw->decryptKey($encrypted_key, $keys, $headers);
    }

    /**
     * @param string $key
     * @return KeySet
     */
    private function createKeySet(string $key): KeySet {
        $keys = new KeySet();
        $keys->add(new SymmetricKey($key, 'bin'));
        return $keys;
    }

    /**
     * Returns the underlying AES key wrap algorithm
     * 
     * @return AESKeyWrap the underlying AES key wrap algorithm
     */
    public function getAESKW(): AESKeyWrap {
        return $this->aeskw;
    }
}

?>