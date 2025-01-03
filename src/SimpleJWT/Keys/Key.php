<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2025
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

use \JsonException;
use SimpleJWT\JWE;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Util\Util;
use SimpleJWT\Util\CBOR\CBOR;
use SimpleJWT\Util\CBOR\DataItem as CBORItem;
use SimpleJWT\Util\CBOR\CBORException;

/**
 * Represents a key.
 */
abstract class Key implements KeyInterface {
    const PEM_PUBLIC = '/-----BEGIN PUBLIC KEY-----([^-:]+)-----END PUBLIC KEY-----/';
    const PEM_PKCS8_PRIVATE = '/-----BEGIN PRIVATE KEY-----([^-:]+)-----END PRIVATE KEY-----/';  // used by PHP 8.1

    /** @var array<int, string> $cose_attribute_map */
    static $cose_attribute_map = [
       1 => 'kty', // tstr / int
       2 => 'kid', // bstr
       3 => 'alg', // tstr / int
       4 => 'key_ops' // [ tstr / int ]
    ];

    /** @var array<int, string> $cose_key_ops_map */
    static $cose_key_ops_map = [
        1 => 'sign',
        2 => 'verify',
        3 => 'encrypt',
        4 => 'decrypt',
        5 => 'wrapKey',
        6 => 'unwrapKey',
        7 => 'deriveKey'
    ];

    /** @var array<string|int, mixed> $data */
    protected $data;

    /** @var string */
    private $thumbnail = null;

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
    public function __construct($data = [], string $format = 'php', ?string $password = null, ?string $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
                if (!is_array($data)) throw new KeyException('Incorrect key data format', KeyException::INVALID_KEY_ERROR);
                $this->data = $data;
                break;
            case 'json':
                if (!is_string($data)) throw new KeyException('Incorrect key data format - string expected', KeyException::INVALID_KEY_ERROR);
                try {
                    $jwk = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

                    if (isset($jwk['ciphertext'])) {
                        $this->data = self::decrypt($data, $password, $alg);
                    } else {
                        $this->data = $jwk;
                    }
                } catch (JsonException $e) {
                    throw new KeyException('Incorrect key data format - malformed JSON', KeyException::INVALID_KEY_ERROR, $e);
                }
                break;
            case 'jwe':
                if (!is_string($data)) throw new KeyException('Incorrect key data format - string expected', KeyException::INVALID_KEY_ERROR);
                $this->data = self::decrypt($data, $password, $alg);
                break;
            case 'cbor':
                try {
                    $cbor = new CBOR();
                    if (is_string($data)) {
                        $cbor_item = $cbor->decode($data, CBORItem::DECODE_CONVERT_BSTR);
                    } else {
                        $cbor_item = $data;
                    }
                    $cbor_item = Util::array_replace_keys($cbor_item, self::$cose_attribute_map);
                    if (isset($cbor_item['key_ops'])) $cbor_item['key_ops'] = Util::array_replace_values($cbor_item['key_ops'], self::$cose_key_ops_map);
                    $this->data = $cbor_item;
                } catch (CBORException $e) {
                    throw new KeyException('Cannot decode CBOR key', KeyException::INVALID_KEY_ERROR, $e);
                }
                break;
        }
    }

    /**
     * Decrypts an encrypted JSON web key
     *
     * @param string $data the underlying key parameters, in JSON web key format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     * @throws KeyException if the key cannot be decrypted, or if the decrypted
     * plaintext is not valid JSON
     * @return array<mixed> the decrypted data
     */
    private static function decrypt(string $data, string $password, string $alg) {
        if ($password == null) {
            throw new KeyException('No password for encrypted key', KeyException::INVALID_KEY_ERROR);
        } else {
            $keys = KeySet::createFromSecret($password, 'bin');
            try {
                $jwe = JWE::decrypt($data, $keys, $alg);
                return json_decode($jwe->getPlaintext(), true, 512, JSON_THROW_ON_ERROR);
            } catch (CryptException $e) {
                throw new KeyException('Cannot decrypt key', KeyException::INVALID_KEY_ERROR, $e);
            } catch (JsonException $e) {
                throw new KeyException('Incorrect key data format - malformed JSON', KeyException::INVALID_KEY_ERROR, $e);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyId(bool $generate = false): ?string {
        if (!isset($this->data['kid']) && $generate) {
            $this->data['kid'] = substr($this->getThumbnail(), 0, 7);
        }
        return isset($this->data['kid']) ? $this->data['kid'] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function setKeyId(string $kid) {
        $this->data['kid'] = $kid;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyType(): string {
        return $this->data['kty'];
    }

    /**
     * {@inheritdoc}
     */
    public function getUse(): ?string {
        return (isset($this->data['use'])) ? $this->data['use'] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function setUse(string $use) {
        $this->data['use'] = $use;
    }

    /**
     * {@inheritdoc}
     */
    public function getOperations(): ?array {
        return (isset($this->data['key_ops'])) ? $this->data['key_ops'] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function setOperations(array $ops) {
        $this->data['key_ops'] = $ops;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyData(): array {
        /** @var array<string, mixed> $data */
        $data = $this->data;
        return $data;
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
     * @return string the JSON web key
     * @throws KeyException if the key cannot be converted
     */
    public function toJWK(string $password = null, string $format = JWE::COMPACT_FORMAT): string {
        $json = json_encode($this->data);
        if ($json == false) throw new KeyException('Cannot encode key', KeyException::INVALID_KEY_ERROR);
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
    abstract protected function getThumbnailMembers(): array;

    /**
     * {@inheritdoc}
     */
    public final function getThumbnail(): string {
        if ($this->thumbnail == null) {
            $members = $this->getThumbnailMembers();
            $signing = [];
            foreach ($members as $member) $signing[$member] = strval($this->data[$member]);
            ksort($signing);
            try {
                $hash_input = json_encode($signing);
                if ($hash_input == false) throw new KeyException('Cannot generate thumbnail', KeyException::SYSTEM_LIBRARY_ERROR);
                $this->thumbnail = Util::base64url_encode(hash('sha256', $hash_input, true));
            } catch (JsonException $e) {
                throw new KeyException('Cannot generate thumbnail', KeyException::SYSTEM_LIBRARY_ERROR, $e);
            }
            
        }
        
        return $this->thumbnail;
    }

    /**
     * Replaces the keys of the underlying parameters with specified replacements.
     * 
     * @param array<mixed, mixed> $replacements
     * @return void
     */
    protected function replaceDataKeys(array $replacements) {
        $this->data = Util::array_replace_keys($this->data, $replacements);
    }

    /**
     * Replaces the value of a specified parameter with specified replacements.
     * 
     * @param string $key
     * @param array<mixed, mixed> $replacements
     * @return void
     */
    protected function replaceDataValues(string $key, array $replacements) {
        if (!isset($this->data[$key])) return;

        if (is_scalar($this->data[$key])) {
            if (isset($replacements[$this->data[$key]]))
                $this->data[$key] = $replacements[$this->data[$key]];
        } elseif (is_array($this->data[$key])) {
            $this->data[$key] = Util::array_replace_values($this->data[$key], $replacements);
        }
    }
}

?>
