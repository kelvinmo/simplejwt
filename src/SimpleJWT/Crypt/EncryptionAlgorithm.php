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

namespace SimpleJWT\Crypt;

/**
 * Interface for content authenticated encryption algorithms.
 */
interface EncryptionAlgorithm {
    /**
     * Encrypts plaintext and provides an authentication value.
     *
     * @param string $plaintext the plaintext to encrypt
     * @param string $cek the content encryption key as a binary string
     * @param string $addtional additional authenticated data as a binary string
     * @param string $iv the initialisation vector, where required, as a base64url
     * encoded string
     * @return array an array containing the following keys: `ciphertext` (the ciphertext),
     * `tag` (the authentication tag), and optionally `iv` (the initialisation vector)
     * with all values as base64url encoded strings
     * @throws CryptException if there is an error in the cryptographic process
     */
    public function encryptAndSign($plaintext, $cek, $additional, $iv = null);

    /**
     * Decrypts ciphertext and verifies the authentication tag.
     *
     * @param string $ciphertext the ciphertext to decrypt, as a base64url encoded
     * string
     * @param string $tag the authentication tag, as a base64url encoded
     * string
     * @param string $cek the content encryption key as a binary string
     * @param string $addtional additional authenticated data as a binary string
     * @return string the plaintext as a binary string
     * @throws CryptException if there is an error in the cryptographic process, including
     * if the authentication tag does not match
     */
    public function decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

    /**
     * Returns the required size of the content encryption key for this algorithm.
     *
     * @return int the required size of the content encryption key in bits
     */
    public function getCEKSize();

    /**
     * Returns the required size of the initialisation vector for this algorithm.
     *
     * @return int the required size of the initialisation vector in bits, or 0
     * if an initialisation vector is not required
     */
    public function getIVSize();
}

?>
