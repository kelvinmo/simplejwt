<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2023
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
abstract class Key implements KeyInterface {
    const PEM_PUBLIC = '/-----BEGIN PUBLIC KEY-----([^-:]+)-----END PUBLIC KEY-----/';
    const PEM_PKCS8_PRIVATE = '/-----BEGIN PRIVATE KEY-----([^-:]+)-----END PRIVATE KEY-----/';  // used by PHP 8.1

    /** @var array<string, mixed> $data */
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
     * @param array<string, mixed>|string $data the underlying key parameters, in JSON web key format
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     * @throws KeyException if the key cannot be created
     */
    public function __construct($data = [], $format = 'php', $password = null, $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
                if (!is_array($data)) throw new KeyException('Incorrect key data format');
                $this->data = $data;
                break;
            case 'json':
                if (!is_string($data)) throw new KeyException('Incorrect key data format - string expected');
                $jwk = json_decode($data, true);

                if ((null === $jwk) && ($json_err = json_last_error_msg())) throw new KeyException('Incorrect key data format - malformed JSON: ' . $json_err);

                if (isset($jwk['ciphertext'])) {
                    $this->data = self::decrypt($data, $password, $alg);
                } else {
                    $this->data = $jwk;
                }
                break;
            case 'jwe':
                if (!is_string($data)) throw new KeyException('Incorrect key data format - string expected');
                $this->data = self::decrypt($data, $password, $alg);
        }
    }

    /**
     * Decrypts an encrypted JSON web key
     *
     * @param string $data the underlying key parameters, in JSON web key format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     * @return array<mixed> the decrypted data
     */
    private static function decrypt($data, $password, $alg) {
        if ($password == null) {
            throw new KeyException('No password for encrypted key');
        } else {
            $keys = KeySet::createFromSecret($password, 'bin');
            try {
                $jwe = JWE::decrypt($data, $keys, $alg);
                return json_decode($jwe->getPlaintext(), true);
            } catch (CryptException $e) {
                throw new KeyException('Cannot decrypt key', 0, $e);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyId(bool $generate = false) {
        if (!isset($this->data['kid']) && $generate) {
            $this->data['kid'] = substr($this->getThumbnail(), 0, 7);
        }
        return isset($this->data['kid']) ? $this->data['kid'] : null;
    }

    /**
     * Sets the key ID
     *
     * @param string $kid the key ID
     * @return void
     */
    public function setKeyId($kid) {
        $this->data['kid'] = $kid;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyType() {
        return $this->data['kty'];
    }

    /**
     * {@inheritdoc}
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
     * @return void
     */
    public function setUse($use) {
        $this->data['use'] = $use;
    }

    /**
     * {@inheritdoc}
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
     * @param array<string> $ops the allowed operations
     * @return void
     */
    public function setOperations($ops) {
        if (!is_array($ops)) $ops = explode(',', $ops);
        $this->data['key_ops'] = $ops;
    }

    /**
     * {@inheritdoc}
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
     * @param string $format the serialisation format for the JWE (ignored if the
     * key is a public key)
     * @return string the key set
     * @throws KeyException if the key cannot be converted
     */
    public function toJWK($password = null, $format = JWE::COMPACT_FORMAT) {
        $json = json_encode($this->data);
        if ($json == false) throw new KeyException('Cannot encode key');
        if (($password == null) || $this->isPublic()) return $json;

        $keys = KeySet::createFromSecret($password, 'bin');
        $headers = [
            'alg' => 'PBES2-HS256+A128KW',
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk+json'
        ];
        $jwe = new JWE($headers, $json);
        return $jwe->encrypt($keys, null, $format);
    }

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
     * @return array<string> the array of keys
     * @see https://tools.ietf.org/html/rfc7638
     */
    abstract protected function getThumbnailMembers();

    /**
     * {@inheritdoc}
     */
    public function getThumbnail() {
        $members = $this->getThumbnailMembers();
        $signing = [];
        foreach ($members as $member) $signing[$member] = strval($this->data[$member]);
        ksort($signing);
        $hash_input = json_encode($signing);
        if ($hash_input == false) throw new KeyException('Cannot generate thumbnail');
        return Util::base64url_encode(hash('sha256', $hash_input, true));
    }
}

?>
