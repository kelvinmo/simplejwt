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

namespace SimpleJWT\Crypt\Signature;

use SimpleJWT\Crypt\AlgorithmInterface;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Keys\KeyInterface;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\KeyException;

/**
 * Interface for signature algorithms.
 */
interface SignatureAlgorithm extends AlgorithmInterface {
    /**
     * Signs a payload.
     *
     * @param string $data the payload to sign
     * @param KeySet $keys the key set containing the key
     * to be used to sign the payload
     * @param string $kid the ID of the key to be used. If null the key will
     * be chosen automatically.
     * @return string the base64url encoded signature
     * @throws KeyException if there is an error in obtaining the
     * key(s) required for this operation
     * @throws CryptException if there is an error in the cryptographic process
     */
    public function sign(string $data, KeySet $keys, ?string $kid = null): string;

    /**
     * Verifies a signature.
     *
     * @param string $signature the base64url encoded signature to verify
     * @param string $data the payload the signature of which is to be verified
     * @param KeySet $keys the key set containing the key
     * to be used to verify the signature
     * @param string $kid the ID of the key to be used. If null the key will
     * be chosen automatically.
     * @return bool true if the signature is valid
     * @throws KeyException if there is an error in obtaining the
     * key(s) required for this operation
     * @throws CryptException if there is an error in the cryptographic process
     */
    public function verify(string $signature, string $data, KeySet $keys, ?string $kid = null): bool;

    /**
     * Obtains the key that will be used to sign the payload.
     *
     * @param KeySet $keys the key set containing the key
     * to be used to sign the payload
     * @param string $kid the ID of the key to be used. If null the key will
     * be chosen automatically.
     * @return KeyInterface|null the signing key, or null if there is no appropriate
     * key in $keys
     */
    public function getSigningKey(KeySet $keys, ?string $kid = null): ?KeyInterface;

    /**
     * Calculates an OpenID Connect short hash of a payload.
     *
     * The short hash is the left-most half of the hash, with the hash algorithm
     * being the one underlying the signature algorithm.  For instance, if the signature
     * algorithm is RS256, the underlying hash algorithm is SHA-256, and this function
     * will return the encoded value of the left-most 128 bits of the SHA-256 hash.
     *
     * @param string $data the data to hash
     * @return string the base64url encoded short hash.
     * @throws CryptException if there is an error in the cryptographic process
     */
    public function shortHash(string $data): string;
}

?>
