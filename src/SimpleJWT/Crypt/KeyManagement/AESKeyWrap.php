<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2026
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

use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Util\Util;
use SimpleJWT\Keys\KeyInterface;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\SymmetricKey;

/**
 * Implementation of the AES Key Wrap algorithms.
 * 
 * @see https://tools.ietf.org/html/rfc7518#section-4.4
 * @see https://tools.ietf.org/html/rfc3394
 */
class AESKeyWrap extends BaseAlgorithm implements KeyEncryptionAlgorithm {

    const RFC3394_IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    /** @var array<string, mixed> $alg_params */
    static protected $alg_params = [
        'A128KW' => ['cipher' => 'AES-128-ECB', 'key' => 16],
        'A192KW' => ['cipher' => 'AES-192-ECB', 'key' => 24],
        'A256KW' => ['cipher' => 'AES-256-ECB', 'key' => 32],
    ];

    public function __construct(?string $alg) {
        parent::__construct($alg);
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAlgs(): array {
        $ciphers = array_map('strtoupper', openssl_get_cipher_methods());
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
        $alg = $this->getAlg();
        $size = self::$alg_params[$alg]['key'] * 8;
        return [
            'kty' => 'oct',
            KeyInterface::SIZE_PROPERTY => $size,
            '~alg' => $this->getAlg(),
            '@use' => 'enc',
            '@key_ops' => ['wrapKey', 'unwrapKey']
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function encryptKey(string $cek, KeySet $keys, array &$headers, ?string $kid = null): string {
        /** @var SymmetricKey $key */
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid', CryptException::KEY_NOT_FOUND_ERROR);
        }

        if ((strlen($cek) % 8) != 0) throw new CryptException('Content encryption key not a multiple of 64 bits', CryptException::INVALID_DATA_ERROR);

        $cipher = self::$alg_params[$this->getAlg()]['cipher'];

        $A = self::RFC3394_IV;
        $P = str_split($cek, 8);
        $R = str_split($cek, 8);
        $n = count($P);

        for ($j = 0; $j <= 5; $j++) {
            for ($i = 0; $i < $n; $i++) {
                $t = $n * $j + ($i + 1);
                $B = openssl_encrypt($A . $R[$i], $cipher, $key->toBinary(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                if ($B == false) {
                    $messages = [];
                    while ($message = openssl_error_string()) $messages[] = $message;
                    throw new CryptException('Cannot encrypt key: ' . implode("\n", $messages), CryptException::SYSTEM_LIBRARY_ERROR);
                }

                $A = $this->msb($B) ^ Util::packInt64($t);
                $R[$i] = $this->lsb($B);
            }
        }

        return Util::base64url_encode($A . implode('', $R));
    }

    /**
     * {@inheritdoc}
     */
    public function decryptKey(string $encrypted_key, KeySet $keys, array $headers, ?string $kid = null): string {
        /** @var SymmetricKey $key */
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid', CryptException::KEY_NOT_FOUND_ERROR);
        }

        $cipher = self::$alg_params[$this->getAlg()]['cipher'];

        $R = str_split(Util::base64url_decode($encrypted_key), 8);
        $A = array_shift($R);
        $n = count($R);

        if ($A == null) {
            throw new CryptException('Encrypted key is too short', CryptException::INVALID_DATA_ERROR);
        }

        for ($j = 5; $j >= 0; $j--) {
            for ($i = $n - 1; $i >= 0; $i--) {
                $t = $n * $j + ($i + 1);
                $B = openssl_decrypt(($A ^ Util::packInt64($t)) . $R[$i], $cipher, $key->toBinary(), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                if ($B == false) {
                    $messages = [];
                    while ($message = openssl_error_string()) $messages[] = $message;
                    throw new CryptException('Cannot decrypt key: ' . implode("\n", $messages), CryptException::SYSTEM_LIBRARY_ERROR);
                }
                $A = $this->msb($B);
                $R[$i] = $this->lsb($B);
            }
        }

        if (!Util::secure_compare($A, self::RFC3394_IV)) {
            throw new CryptException('AES key wrap integrity check failed', CryptException::VALIDATION_FAILED_ERROR);
        }

        return implode('', $R);
    }

    /**
     * Returns the most significant half of a specified value
     *
     * @param string $x the value
     * @return string the most significant half
     */
    protected function msb(string $x): string {
        return substr($x, 0, (int) (strlen($x) / 2));
    }

    /**
     * Returns the least significant half of a specified value
     *
     * @param string $x the value
     * @return string the least significant half
     */
    protected function lsb(string $x): string {
        return substr($x, (int) (strlen($x) / 2));
    }

}

?>
