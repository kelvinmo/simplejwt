<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015
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

namespace SimpleJWT\Keys;

use SimpleJWT\Util\Util;

/**
 * Represents a key.
 */
abstract class Key {
    const PEM_PUBLIC = '/-----BEGIN PUBLIC KEY-----([^-:]+)-----END PUBLIC KEY-----/';

    const SIZE_PROPERTY = '#size';
    const PUBLIC_PROPERTY = '#public';

    protected $data;

    /**
     * Creates a key
     *
     * @param array the underlying key parameters, in JSON web key format
     */
    public function __construct($data = array()) {
        $this->data = $data;
        if (!isset($data['kid'])) {
            $this->data['kid'] = substr($this->getSignature(), 0, 7);
        }
    }

    /**
     * Returns the key ID
     *
     * @return string the key ID
     */
    public function getKeyId() {
        return $this->data['kid'];
    }

    /**
     * Sets the key ID
     *
     * @param string $kid the key ID
     */
    public function setKeyId($kid) {
        $this->data['kid'] = $kid;
    }

    /**
     * Returns the type of the key
     *
     * @return string the type
     */
    public function getKeyType() {
        return $this->data['kty'];
    }

    /**
     * Returns the allowed usage for the key
     *
     * @return string the allowed usage
     */
    public function getUse() {
        return (isset($this->data['use'])) ? $this->data['use'] : null;
    }

    /**
     * Sets the allowed usage for the key
     *
     * The usage can be one of: sig, enc
     *
     * @param string $use the allowed usage
     */
    public function setUse($use) {
        $this->data['use'] = $use;
    }

    /**
     * Returns the allowed operations for the key
     *
     * @return array the allowed operations
     */
    public function getOperations() {
        return (isset($this->data['key_ops'])) ? $this->data['key_ops'] : null;
    }

    /**
     * Sets the allowed operations for the key
     *
     * The values can be one or more of: sign, verify, encrypt, decrypt
     * wrapKey, unwrapKey, deriveKey, deriveBits
     *
     * @param array $ops the allowed operations
     */
    public function setOperations($ops) {
        if (!is_array($ops)) $ops = explode(',', $ops);
        $this->data['key_ops'] = $ops;
    }

    /**
     * Returns the size of the key, in bits.  The definition of "size"
     * is dependent on the key algorithm.
     *
     * @return int the size of the key in bits
     */
    abstract public function getSize();

    /**
     * Determines wshether the key is a public key.
     *
     * A key is public if, and only if, it is an asymmetric key, and the key
     * does not contain any private parameters.
     *
     * @return bool true if the key is public
     */
    abstract public function isPublic();

    /**
     * Returns the public key.
     *
     * @return Key the public key, or null if the public key does not exist (e.g. is a symmetric key)
     */
    abstract public function getPublicKey();

    /**
     * Returns the underlying parameters for the key
     *
     * @return array the parameters
     */
    public function getKeyData() {
        return $this->data;
    }

    /**
     * Returns the key in JSON format
     *
     * @return string the key in JSON format
     */
    public function toJSON() {
        return json_encode($this->data);
    }

    /**
     * Returns the key in PEM (base64 encoded DER) format
     *
     * @return string the key in PEM format
     * @throws KeyException if the key cannot be converted
     */
    abstract public function toPEM();

    /**
     * Obtains the keys from the underlying JSON web key object to be used
     * to calculate the key's signature.
     *
     * Generally, the following should be returned:
     *
     * - `kty`
     * - `alg` (if exists)
     * - if it is a symmetric key, the key itself
     * - if it is an asymmetric key, all the parameters for the public key
     *
     * @return array the array of keys
     */
    abstract protected function getSignatureKeys();

    /**
     * Obtains a signature for the key.  The signature is derived from the
     * keys to the JSON web key object as returned by the {@link getSignatureKeys()}
     * function.
     *
     * For asymmetric keys, the public and private keys should have the same
     * signature.
     *
     * @return string the signature
     */
    public function getSignature() {
        $keys = $this->getSignatureKeys();
        $signing = array();
        foreach ($keys as $key) $signing[$key] = $this->data[$key];
        ksort($signing);
        return Util::base64url_encode(hash('sha256', json_encode($signing), true));
    }
}

?>
