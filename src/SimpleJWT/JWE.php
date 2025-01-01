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
namespace SimpleJWT;

use \JsonException;
use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Crypt\Encryption\EncryptionAlgorithm;
use SimpleJWT\Crypt\KeyManagement\KeyManagementAlgorithm;
use SimpleJWT\Crypt\KeyManagement\KeyDerivationAlgorithm;
use SimpleJWT\Crypt\KeyManagement\KeyEncryptionAlgorithm;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Keys\KeyException;
use SimpleJWT\Util\Helper;
use SimpleJWT\Util\Util;

/**
 * A JSON web encryption (JWE) object.
 * 
 * A JWE consists of a header and ciphertext.  To create a JWE, use the
 * constructor with the header and plaintext as the parameter.  The JWE can then
 * be encrypted using the {@link encrypt()} function.
 *
 * To decrypt a JWE, use the {@link decrypt()} static function.  If
 * successful, the static function will return a JWE object.  The plaintext
 * can then be retrieved using the {@link getPlaintext()} function.
 */
class JWE extends Token {
    /** @var array<string, mixed> $headers */
    protected $headers = ['typ' => 'JWE'];

    /** @var string $plaintext */
    protected $plaintext = null;

    /**
     * Creates a new JWE.
     *
     * @param array<string, mixed> $headers the headers
     * @param string $plaintext the plaintext to encrypt
     */
    public function __construct(array $headers, string $plaintext) {
        parent::__construct($headers);
        $this->plaintext = $plaintext;
    }

    /**
     * Decrypts a JWE.
     *
     * @param string $token the serialised JWE
     * @param KeySet $keys the key set containing the key to verify the
     * JWT's signature
     * @param string $expected_alg the expected value of the `alg` parameter, which
     * should be agreed between the parties out-of-band
     * @return JWE the decrypted JWE
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    public static function decrypt(string $token, KeySet $keys, string $expected_alg): JWE {
        $detect_result = Helper::detect($token);
        if ($detect_result == null)
            throw new InvalidTokenException('Unrecognised token format', InvalidTokenException::TOKEN_PARSE_ERROR);
        $format = $detect_result['format'];

        switch ($format) {
            case self::COMPACT_FORMAT:
                $parts = explode('.', $token, 5);
                if (count($parts) != 5) throw new InvalidTokenException('Cannot decode compact serialisation', InvalidTokenException::TOKEN_PARSE_ERROR);
                list($protected, $encrypted_key, $iv, $ciphertext, $tag) = $parts;
                break;
            case self::JSON_FORMAT:
                try {
                    $obj = json_decode($token, true, 512, JSON_THROW_ON_ERROR);
                    
                    $protected = $obj['protected'];
                    $unprotected = (isset($obj['unprotected'])) ? $obj['unprotected'] : [];
                    $iv = $obj['iv'];
                    $ciphertext = $obj['ciphertext'];
                    $tag = $obj['tag'];

                    if (isset($obj['recipients'])) {
                        foreach ($obj['recipients'] as $recipient) {
                            if (isset($recipient['header']['kid'])) {
                                $target_kid = $recipient['header']['kid'];
                                if ($keys->getById($target_kid) != null) {
                                    if (isset($recipient['header'])) $unprotected = array_merge($unprotected, $recipient['header']);
                                    $encrypted_key = $recipient['encrypted_key'];
                                    break;
                                }
                            }
                        }
                        if (!isset($encrypted_key)) throw new InvalidTokenException('Cannot find recipient with decryptable key', InvalidTokenException::DECRYPTION_ERROR);
                    } else {
                        if (isset($obj['header'])) $unprotected = array_merge($unprotected, $obj['header']);
                        $encrypted_key = (isset($obj['encrypted_key'])) ? $obj['encrypted_key'] : '';
                    }
                } catch (JsonException $e) {
                    throw new InvalidTokenException('Cannot decode JSON', InvalidTokenException::TOKEN_PARSE_ERROR, $e);
                }
                break;
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }

        try {
            $headers = json_decode(Util::base64url_decode($protected), true, 512, JSON_THROW_ON_ERROR);
            if (isset($unprotected)) $headers = array_merge($headers, $unprotected);
        } catch (JsonException $e) {
            throw new InvalidTokenException('Cannot decode header', InvalidTokenException::TOKEN_PARSE_ERROR, $e);
        }

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
        if (!($key_enc instanceof KeyManagementAlgorithm))
            throw new InvalidTokenException('Invalid key algorithm: ' . $headers['alg'], InvalidTokenException::DECRYPTION_ERROR);

        /** @var EncryptionAlgorithm $content_enc */
        $content_enc = AlgorithmFactory::create($headers['enc']);
        if (!($content_enc instanceof EncryptionAlgorithm))
            throw new InvalidTokenException('Invalid content encryption algorithm: ' . $headers['enc'], InvalidTokenException::DECRYPTION_ERROR);

        $key_decryption_keys = $keys;

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

                $key_decryption_keys = new KeySet();
                $key_decryption_keys->add($agreed_symmetric_key);
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
                $cek = $key_enc->decryptKey($encrypted_key, $key_decryption_keys, $headers, $kid);
            } catch (KeyException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            } catch (CryptException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            }
        }

        if (!isset($cek)) throw new InvalidTokenException('alg parameter incorrect', InvalidTokenException::TOKEN_PARSE_ERROR);

        try {
            $plaintext = $content_enc->decryptAndVerify($ciphertext, $tag, $cek, $protected, $iv);

            if (isset($headers['zip'])) {
                switch ($headers['zip']) {
                    case 'DEF':
                        $plaintext = gzinflate($plaintext);
                        if ($plaintext == false) throw new InvalidTokenException('Cannot decompress plaintext', InvalidTokenException::TOKEN_PARSE_ERROR);
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
     * Returns the JWE's plaintext
     *
     * @return string the plaintext
     */
    public function getPlaintext(): string {
        return $this->plaintext;
    }

    /**
     * Encrypts the JWE.
     *
     * @param KeySet $keys the key set containing the key to encrypt the
     * content encryption key
     * @param string $kid the ID of the key to use to encrypt. If null, this
     * is automatically retrieved
     * @param string $format the JWE serialisation format, should be one of
     * {@link Token::COMPACT_FORMAT} or {@link Token::JSON_FORMAT}
     * @return string the encrypted JWE
     * @throws \SimpleJWT\Keys\KeyException if there is an error obtaining the key
     * to sign the JWT
     * @throws \SimpleJWT\Crypt\CryptException if there is a cryptographic error
     */
    public function encrypt(KeySet $keys, ?string $kid = null, string $format = self::COMPACT_FORMAT) {
        if (!isset($this->headers['alg'])) throw new \InvalidArgumentException('alg parameter missing');
        if (!isset($this->headers['enc'])) throw new \InvalidArgumentException('enc parameter missing');

        $key_enc = AlgorithmFactory::create($this->headers['alg']);
        if (!($key_enc instanceof KeyManagementAlgorithm))
            throw new \InvalidArgumentException('Invalid key algorithm: ' . $this->headers['alg']);
        
        /** @var EncryptionAlgorithm $content_enc */
        $content_enc = AlgorithmFactory::create($this->headers['enc']);
        if (!($content_enc instanceof EncryptionAlgorithm))
            throw new \InvalidArgumentException('Invalid content encryption algorithm: ' . $this->headers['enc']);

        $key_encryption_keys = $keys;

        if ($kid != null) $this->headers['kid'] = $kid;

        if ($key_enc instanceof KeyDerivationAlgorithm) {
            $agreed_key = $key_enc->deriveKey($keys, $this->headers, $kid);

            if ($key_enc instanceof KeyEncryptionAlgorithm) {
                // Key agreement with wrapping
                $agreed_symmetric_key = new SymmetricKey([
                    'kty' => SymmetricKey::KTY,
                    'alg' => $this->headers['alg'],
                    'k' => Util::base64url_encode($agreed_key),
                ], 'php');
                $kid = $agreed_symmetric_key->getThumbnail();
                $agreed_symmetric_key->setKeyId($kid);

                $key_encryption_keys = new KeySet();
                $key_encryption_keys->add($agreed_symmetric_key);
            } else {
                // Direct key agreement or direct encryption
                $cek = $agreed_key;
            }
        }

        if (!isset($cek)) {
            /** @var int<1, max> $cek_size */
            $cek_size = (int) ($content_enc->getCEKSize() / 8);
            $cek = $this->generateCEK($cek_size);
        }

        if ($key_enc instanceof KeyEncryptionAlgorithm) {
            $encrypted_key = $key_enc->encryptKey($cek, $key_encryption_keys, $this->headers, $kid);
        } else {
            $encrypted_key = '';
        }

        if (isset($this->headers['zip'])) {
            switch ($this->headers['zip']) {
                case 'DEF':
                    $plaintext = gzdeflate($this->plaintext);
                    if ($plaintext == false) throw new \InvalidArgumentException('Cannot compress plaintext');
                    break;
                default:
                    throw new \InvalidArgumentException('Unsupported zip header:' . $this->headers['zip']);
            }
        } else {
            $plaintext = $this->plaintext;
        }

        $protected = Util::base64url_encode((string) json_encode($this->headers));
        
        if ($content_enc->getIVSize() > 0) {
            /** @var int<0, max> $iv_size */
            $iv_size = (int) ($content_enc->getIVSize() / 8);
            $iv = $this->generateIV($iv_size);
        } else {
            $iv = '';
        }

        $results = $content_enc->encryptAndSign($plaintext, $cek, $protected, $iv);

        $ciphertext = $results['ciphertext'];
        if (isset($results['iv'])) $iv = $results['iv'];
        $tag = $results['tag'];

        switch ($format) {
            case self::COMPACT_FORMAT:
                return $protected . '.' . $encrypted_key . '.' . $iv . '.' . $ciphertext . '.' . $tag;
            case self::JSON_FORMAT:
                $obj = [
                    'protected' => $protected,
                    'ciphertext' => $ciphertext,
                    'tag' => $tag
                ];
                if ($encrypted_key) $obj['encrypted_key'] = $encrypted_key;
                if ($iv) $obj['iv'] = $iv;

                return (string) json_encode($obj);
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }
    }

    /**
     * Generates a content encryption key.
     * 
     * (This method is separated from the rest of the {@link encrypt()}
     * function to enable testing.)
     * 
     * @param int<1, max> $length the length of the content encryption key, in bytes
     * @return string the generated content encryption key as a binary
     * string
     */
    protected function generateCEK(int $length): string {
        return Util::random_bytes($length);
    }

    /**
     * Generates a initialisation vector.
     * 
     * (This method is separated from the rest of the {@link encrypt()}
     * function to enable testing.)
     * 
     * @param int<0, max> $length the length of the initialisation vector, in bytes
     * @return string the generated initialisation vector as a base64url
     * encoded string
     */
    protected function generateIV(int $length): string {
        if ($length <= 0) return '';
        return Util::base64url_encode(Util::random_bytes($length));
    }
}

?>
