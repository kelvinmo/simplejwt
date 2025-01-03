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

namespace SimpleJWT\Crypt\Encryption;

use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Util\Util;

/**
 * Implementation of the AES_CBC_HMAC_SHA2 family of algorithms.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.2
 */
class AESCBC_HMACSHA2 extends BaseAlgorithm implements EncryptionAlgorithm {
    /** @var array<string, mixed> $alg_params */
    static protected $alg_params = [
        'A128CBC-HS256' => ['cipher' => 'AES-128-CBC', 'hash' => 'sha256', 'key' => 32, 'tag' => 16],
        'A192CBC-HS384' => ['cipher' => 'AES-192-CBC', 'hash' => 'sha384', 'key' => 48, 'tag' => 24],
        'A256CBC-HS512' => ['cipher' => 'AES-256-CBC', 'hash' => 'sha512', 'key' => 64, 'tag' => 32],
    ];

    public function __construct(?string $alg) {
        parent::__construct($alg);
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAlgs(): array {
        $ciphers = array_map('strtoupper', openssl_get_cipher_methods());
        $hashes = hash_algos();
        $results = [];

        foreach (self::$alg_params as $alg => $param) {
            if (in_array($param['cipher'], $ciphers) && in_array($param['hash'], $hashes)) {
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

        $split = (int) (strlen($cek) / 2);
        if ($split < 1) throw new CryptException('Incorrect key length', CryptException::INVALID_DATA_ERROR);
        list($mac_key, $enc_key) = str_split($cek, $split);
        $al = Util::packInt64(strlen($additional) * 8);

        $e = openssl_encrypt($plaintext, $params['cipher'], $enc_key, OPENSSL_RAW_DATA, $iv);
        if ($e == false) {
            $messages = [];
            while ($message = openssl_error_string()) $messages[] = $message;
            throw new CryptException('Cannot encrypt plaintext: ' . implode("\n", $messages), CryptException::SYSTEM_LIBRARY_ERROR);
        }

        $m = hash_hmac($params['hash'], $additional . $iv . $e . $al, $mac_key, true);
        $t = substr($m, 0, $params['tag']);

        return [
            'ciphertext' => Util::base64url_encode($e),
            'tag' => Util::base64url_encode($t),
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

        $split = (int) (strlen($cek) / 2);
        if ($split < 1) throw new CryptException('Incorrect key length', CryptException::INVALID_DATA_ERROR);
        list($mac_key, $enc_key) = str_split($cek, $split);
        list($mac_key, $enc_key) = str_split($cek, $split);
        $al = Util::packInt64(strlen($additional) * 8);

        $e = Util::base64url_decode($ciphertext);
        $m = hash_hmac($params['hash'], $additional . $iv . $e . $al, $mac_key, true);
        $t = substr($m, 0, $params['tag']);

        if (!Util::secure_compare(Util::base64url_decode($tag), $t)) throw new CryptException('Authentication tag does not match', CryptException::VALIDATION_FAILED_ERROR);
        
        $plaintext = openssl_decrypt($e, $params['cipher'], $enc_key, OPENSSL_RAW_DATA, $iv);
        if ($plaintext == false) {
            $messages = [];
            while ($message = openssl_error_string()) $messages[] = $message;
            throw new CryptException('Cannot decrypt ciphertext: ' . implode("\n", $messages), CryptException::SYSTEM_LIBRARY_ERROR);
        }

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
        return 128;
    }
}

?>
