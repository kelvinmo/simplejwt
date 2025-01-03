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

namespace SimpleJWT\Crypt\Encryption;

use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Util\Util;

/**
 * Implementation of the AES GCM family of algorithms.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.3
 */
class AESGCM extends BaseAlgorithm implements EncryptionAlgorithm {
    /** @var array<string, mixed> $alg_params */
    static protected $alg_params = [
        'A128GCM' => ['cipher' => 'aes-128-gcm', 'key' => 16],
        'A192GCM' => ['cipher' => 'aes-192-gcm', 'key' => 24],
        'A256GCM' => ['cipher' => 'aes-256-gcm', 'key' => 32],
    ];

    /** Size of the authentication tag in bits */
    const TAG_SIZE = 128;

    public function __construct(?string $alg) {
        parent::__construct($alg);
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAlgs(): array {
        $ciphers = array_map('strtolower', openssl_get_cipher_methods());
        $results = [];

        foreach (self::$alg_params as $alg => $param) {
            if (in_array($param['cipher'], $ciphers)) {
                $results[] = $alg;
            }
        }

        return $results;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyCriteria(): array {
        return ['kty' => 'oct', '@use' => 'enc', '@key_ops' => ['encrypt', 'decrypt']];
    }

    /**
     * {@inheritdoc}
     */
    public function encryptAndSign(string $plaintext, string $cek, string $additional, ?string $iv): array {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) throw new CryptException('Incorrect key length', CryptException::INVALID_DATA_ERROR);

        if ($iv == null) {
            $iv = openssl_random_pseudo_bytes($this->getIVSize() / 8);
        } else {
            $iv = Util::base64url_decode($iv);
            if (strlen($iv) != $this->getIVSize() / 8) throw new CryptException('Incorrect IV length', CryptException::INVALID_DATA_ERROR);
        }

        $e = openssl_encrypt($plaintext, $params['cipher'], $cek, OPENSSL_RAW_DATA, $iv, $tag, $additional, self::TAG_SIZE / 8);
        if ($e == false) {
            $messages = [];
            while ($message = openssl_error_string()) $messages[] = $message;
            throw new CryptException('Cannot encrypt plaintext: ' . implode("\n", $messages), CryptException::SYSTEM_LIBRARY_ERROR);
        }

        return [
            'ciphertext' => Util::base64url_encode($e),
            'tag' => Util::base64url_encode($tag),
            'iv' => Util::base64url_encode($iv),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function decryptAndVerify(string $ciphertext, string $tag, string $cek, string $additional, string $iv): string {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) throw new CryptException('Incorrect key length', CryptException::INVALID_DATA_ERROR);

        $iv = Util::base64url_decode($iv);
        if (strlen($iv) != $this->getIVSize() / 8) throw new CryptException('Incorrect IV length', CryptException::INVALID_DATA_ERROR);

        $tag = Util::base64url_decode($tag);
        if (strlen($tag) != self::TAG_SIZE / 8) throw new CryptException('Incorrect authentication tag length', CryptException::INVALID_DATA_ERROR);
        
        $plaintext = openssl_decrypt(Util::base64url_decode($ciphertext), $params['cipher'], $cek, OPENSSL_RAW_DATA, $iv, $tag, $additional);
        if ($plaintext === false) throw new CryptException('Authentication tag does not match', CryptException::VALIDATION_FAILED_ERROR);

        return $plaintext;
    }

    /**
     * {@inheritdoc}
     */
    public function getCEKSize() {
        return 8 * self::$alg_params[$this->getAlg()]['key'];
    }

    /**
     * {@inheritdoc}
     */
    public function getIVSize() {
        return 96;
    }
}

?>
