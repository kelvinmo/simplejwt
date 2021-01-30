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
namespace SimpleJWT;

use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Crypt\KeyDerivationAlgorithm;
use SimpleJWT\Crypt\KeyEncryptionAlgorithm;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Util\Helper;
use SimpleJWT\Util\Util;

class JWE {
    /** @var string COMPACT_FORMAT Compact JWE serialisation format */
    const COMPACT_FORMAT = Helper::COMPACT_FORMAT;
    /** @var string JSON_FORMAT JSON JWE serialisation format */
    const JSON_FORMAT = Helper::JSON_FORMAT;

    protected $headers = ['typ' => 'JWE'];

    protected $plaintext = null;

    /**
     * Creates a new JWE.
     *
     * @param array $headers the headers
     * @param array $plaintext the plaintext to encrypt
     */
    public function __construct($headers, $plaintext) {
        $this->headers = $headers;
        $this->plaintext = $plaintext;
    }

    /**
     * Decrypts a JWE.
     *
     * @param string $token the serialised JWE
     * @param \SimpleJWT\Keys\KeySet $keys the key set containing the key to verify the
     * JWT's signature
     * @param string $expected_alg the expected value of the `alg` parameter, which
     * should be agreed between the parties out-of-band
     * @return JWE the decrypted JWE
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    public static function decrypt($token, $keys, $expected_alg) {
        $detect_result = Helper::detect($token);
        $format = $detect_result['format'];

        switch ($format) {
            case self::COMPACT_FORMAT:
                $parts = explode('.', $token, 5);
                if (count($parts) != 5) throw new InvalidTokenException('Cannot decode compact serialisation', InvalidTokenException::TOKEN_PARSE_ERROR);
                list($protected, $encrypted_key, $iv, $ciphertext, $tag) = $parts;
                break;
            case self::JSON_FORMAT:
                $obj = json_decode($token, true);
                if ($obj == null) throw new InvalidTokenException('Cannot decode JSON', InvalidTokenException::TOKEN_PARSE_ERROR);
                $protected = $obj['protected'];
                $unprotected = $obj['unprotected'];
                $iv = $obj['iv'];
                $ciphertext = $obj['ciphertext'];
                $tag = $obj['tag'];

                if (isset($obj['recipients'])) {
                    foreach ($obj['recipients'] as $recipient) {
                        if (isset($recipient_obj['header']['kid'])) {
                            $target_kid = $recipient_obj['header']['kid'];
                            if ($keys->getById($target_kid) != null) {
                                $unprotected = (isset($unprotected)) ? array_merge($unprotected, $recipient_obj['header']) : $recipient_obj['header'];
                                $encrypted_key = $recipient_obj['encrypted_key'];
                                break;
                            }
                        }
                        throw new InvalidTokenException('Cannot find verifiable signature', InvalidTokenException::TOKEN_PARSE_ERROR);
                    }
                } else {
                    $unprotected = (isset($unprotected)) ? array_merge($unprotected, $obj['header']) : $obj['header'];
                    $encrypted_key = $obj['encrypted_key'];
                }
                break;
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }

        $headers = json_decode(Util::base64url_decode($protected), true);
        if ($headers == null) throw new InvalidTokenException('Cannot decode header', InvalidTokenException::TOKEN_PARSE_ERROR);
        if (isset($unprotected)) $headers = array_merge($headers, $unprotected);

        // Process crit
        if (isset($headers['crit'])) {
            foreach ($headers['crit'] as $critical) {
                if (!in_array($critical, array('alg', 'enc', 'kid', 'zip'))) {
                    throw new InvalidTokenException('Critical header not supported: ' . $critical, InvalidTokenException::UNSUPPORTED_ERROR);
                }
            }
        }

        if (!isset($headers['alg'])) throw new InvalidTokenException('alg parameter missing', InvalidTokenException::TOKEN_PARSE_ERROR);
        if (!isset($headers['enc'])) throw new InvalidTokenException('enc parameter missing', InvalidTokenException::TOKEN_PARSE_ERROR);

        if ($headers['alg'] != $expected_alg) throw new InvalidTokenException('Unexpected algorithm', InvalidTokenException::DECRYPTION_ERROR);
        $key_enc = AlgorithmFactory::create($headers['alg']);
        $content_enc = AlgorithmFactory::create($headers['enc']);

        if ($key_enc instanceof KeyDerivationAlgorithm) {
            try {
                $kid = (isset($headers['kid'])) ? $headers['kid'] : null;
                $agreed_key = $key_enc->deriveKey($keys, $headers, $kid);
            } catch (KeyException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            } catch (CryptException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            }

            if ($key_enc instanceof KeyEncryptionAlgorithm) {
                // Key agreement with wrapping
                $agreed_symmetric_key = new SymmetricKey([
                    'kty' => SymmetricKey::KTY,
                    'alg' => $headers['alg'],
                    'k' => Util::base64url_encode($agreed_key),
                ], 'php');
                $kid = $agreed_symmetric_key->getThumbnail();
                $agreed_symmetric_key->setKeyId($kid);
                $keys->add($agreed_symmetric_key);
            } else {
                // Direct key agreement or direct encryption
                $cek = $agreed_key;

                if ($encrypted_key != '') {
                    throw new InvalidTokenException('encrypted key should be empty', InvalidTokenException::TOKEN_PARSE_ERROR);
                }
            }
        }

        if (!isset($cek) && ($key_enc instanceof KeyEncryptionAlgorithm)) {
            try {
                if (!isset($kid)) $kid = (isset($headers['kid'])) ? $headers['kid'] : null;
                $cek = $key_enc->decryptKey($encrypted_key, $keys, $headers, $kid);
            } catch (KeyException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            } catch (CryptException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            }
        }

        if (!$cek) throw new InvalidTokenException('alg parameter incorrect', InvalidTokenException::TOKEN_PARSE_ERROR);

        try {
            $plaintext = $content_enc->decryptAndVerify($ciphertext, $tag, $cek, $protected, $iv);

            if (isset($headers['zip'])) {
                switch ($headers['zip']) {
                    case 'DEF':
                        $plaintext = gzinflate($plaintext);
                        break;
                    default:
                        throw new InvalidTokenException('Unsupported zip header:' . $headers['zip'], InvalidTokenException::UNSUPPORTED_ERROR);
                }
            }
        } catch (CryptException $e) {
            throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
        }

        return new JWE($headers, $plaintext);
    }

    /**
     * Returns the JWE's headers.
     *
     * @return array the headers
     */
    public function getHeaders() {
        return $this->headers;
    }

    /**
     * Returns a specified header
     *
     * @param string $header the header to return
     * @return mixed the header value
     */
    public function getHeader($header) {
        return $this->headers[$header];
    }

    /**
     * Returns the JWE's plaintext
     *
     * @return string the plaintext
     */
    public function getPlaintext() {
        return $this->plaintext;
    }

    /**
     * Encrypts the JWE.
     *
     * @param \SimpleJWT\Keys\KeySet $keys the key set containing the key to encrypt the
     * content encryption key
     * @param string $kid the ID of the key to use to encrypt. If null, this
     * is automatically retrieved
     * @param string $format the JWE serialisation format
     * @return string the encrypted JWE
     * @throws \SimpleJWT\Keys\KeyException if there is an error obtaining the key
     * to sign the JWT
     * @throws \SimpleJWT\Crypt\CryptException if there is a cryptographic error
     */
    public function encrypt($keys, $kid = null, $format = self::COMPACT_FORMAT) {
        if (!isset($this->headers['alg'])) throw new \InvalidArgumentException('alg parameter missing');
        if (!isset($this->headers['enc'])) throw new \InvalidArgumentException('enc parameter missing');

        $key_enc = AlgorithmFactory::create($this->headers['alg']);
        $content_enc = AlgorithmFactory::create($this->headers['enc']);

        if ($kid != null) $this->headers['kid'] = $kid;

        if ($key_enc instanceof KeyDerivationAlgorithm) {
            $agreed_key = $key_enc->deriveKey($keys, $this->headers, $kid);

            if ($key_enc instanceof KeyEncryptionAlgorithm) {
                // Key agreement with wrapping
                $agreed_symmetric_key = new SymmetricKey([
                    'kty' => SymmetricKey::KTY,
                    'alg' => $headers['alg'],
                    'k' => Util::base64url_encode($agreed_key),
                ], 'php');
                $kid = $agreed_symmetric_key->getThumbnail();
                $agreed_symmetric_key->setKeyId($kid);
                $keys->add($agreed_symmetric_key);
            } else {
                // Direct key agreement or direct encryption
                $cek = $agreed_key;
            }
        }

        if (!isset($cek)) $cek = Util::random_bytes($content_enc->getCEKSize() / 8);

        if ($key_enc instanceof KeyEncryptionAlgorithm) {
            $encrypted_key = $key_enc->encryptKey($cek, $keys, $this->headers, $kid);
        } else {
            $encrypted_key = '';
        }

        if (isset($this->headers['zip'])) {
            switch ($this->headers['zip']) {
                case 'DEF':
                    $plaintext = gzdeflate($this->plaintext);
                    break;
                default:
                    throw new \InvalidArgumentException('Unsupported zip header:' . $this->headers['zip']);
            }
        } else {
            $plaintext = $this->plaintext;
        }

        $protected = Util::base64url_encode(json_encode($this->headers));
        $results = $content_enc->encryptAndSign($plaintext, $cek, $protected);

        $ciphertext = $results['ciphertext'];
        $iv = (isset($results['iv'])) ? $results['iv'] : '';
        $tag = $results['tag'];

        switch ($format) {
            case self::COMPACT_FORMAT:
                return $protected . '.' . $encrypted_key . '.' . $iv . '.' . $ciphertext . '.' . $tag;
            case self::JSON_FORMAT:
                $obj = [
                    'protected' => $protected,
                    'ciphertext' => $ciphertext,
                    'tag' => $tag,
                    'encrypted_key' => $encrypted_key
                ];
                if ($iv) $obj['iv'] = $iv;

                return json_encode($obj);
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }
    }
}

?>
