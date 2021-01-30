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

namespace SimpleJWT\Keys;

use SimpleJWT\JWE;
use SimpleJWT\Crypt\CryptException;
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
     * Creates a key.  By default the following formats are supported:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `jwe` - Encrypted JSON web key
     *
     * Subclasses may support additional formats.
     *
     * @param array $data the underlying key parameters, in JSON web key format
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     */
    public function __construct($data = [], $format = 'php', $password = null, $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
                $this->data = $data;
                break;
            case 'json':
                $jwk = json_decode($data, true);

                if (isset($jwk['ciphertext'])) {
                    $this->data = self::decrypt($data, $password, $alg);
                } else {
                    $this->data = $jwk;
                }
                break;
            case 'jwe':
                $this->data = self::decrypt($data, $password, $alg);
        }

        if (!isset($data['kid'])) {
            $this->data['kid'] = substr($this->getThumbnail(), 0, 7);
        }
    }

    /**
     * Decrypts an encrypted JSON web key
     *
     * @param array $data the underlying key parameters, in JSON web key format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     * @return array the decrypted data
     */
    private static function decrypt($data, $password, $alg) {
        if ($password == null) {
            throw new KeyException('No password for encrypted key');
        } else {
            $keys = KeySet::createFromSecret($password, 'bin');
            try {
                $jwe = JWE::decrypt($data, $keys, $alg, (isset($data['ciphertext'])) ? JWE::JSON_FORMAT : JWE::COMPACT_FORMAT);
                return json_decode($jwe->getPlaintext());
            } catch (CryptException $e) {
                throw new KeyException('Cannot decrypt key', 0, $e);
            }
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
     * Returns a key as a JSON web key.
     *
     * If `$password` is null or if the key is a public key, an unencrypted JSON
     * structure is returned.
     *
     * If `$password` is not null and the key is a private key, a JWE is created
     * using PBES2 key encryption.
     *
     * @param string $password the password
     * @return string the key set
     */
    public function toJWK($password = null) {
        $json = json_encode($this->data);
        if (($password == null) || $this->isPublic()) return $json;

        $keys = KeySet::createFromSecret($password, 'bin');
        $headers = [
            'alg' => 'PBES2-HS256+A128KW',
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk+json'
        ];
        $jwe = new JWE($headers, $json);
        return $jwe->encrypt($keys);
    }

    /**
     * Returns the key in PEM (base64 encoded DER) format
     *
     * @return string the key in PEM format
     * @throws KeyException if the key cannot be converted
     */
    abstract public function toPEM();

    /**
     * Obtains the members from the underlying JSON web key object to be used
     * to calculate the key's thumbnail.
     * 
     * The members are specified in RFC 7638.  Generally, this includes:
     *
     * - `kty`
     * - if it is a symmetric key, the key itself
     * - if it is an asymmetric key, all the parameters for the public key
     *
     * @return array the array of keys
     * @see https://tools.ietf.org/html/rfc7638
     */
    abstract protected function getThumbnailMembers();

    /**
     * Obtains a thumbnail for the key.  The thumbnail is derived from the
     * keys to the JSON web key object as returned by the {@link getThumbnailMembers()}
     * function.
     *
     * For asymmetric keys, the public and private keys should have the same
     * thumbnail.
     *
     * @return string the thumbnail
     */
    public function getThumbnail() {
        $members = $this->getThumbnailMembers();
        $signing = [];
        foreach ($members as $member) $signing[$member] = strval($this->data[$member]);
        ksort($signing);
        return Util::base64url_encode(hash('sha256', json_encode($signing), true));
    }
}

?>
