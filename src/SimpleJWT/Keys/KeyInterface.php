<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2023-2026
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

/**
 * Interface for cryptographic keys
 */
interface KeyInterface {
    const SIZE_PROPERTY = '#size';
    const PUBLIC_PROPERTY = '#public';

    /**
     * Returns the key ID
     *
     * @param bool $generate whether to generate the key ID if it is not
     * present
     * @return string|null the key ID
     */
    public function getKeyId(bool $generate = false): ?string;

    /**
     * Sets the key ID
     *
     * @param string $kid the key ID
     * @return void
     */
    public function setKeyId(string $kid);

    /**
     * Returns the type of the key
     *
     * @return string the type
     */
    public function getKeyType(): string;

    /**
     * Returns the allowed usage for the key
     *
     * @return string the allowed usage
     */
    public function getUse(): ?string;

    /**
     * Sets the allowed usage for the key
     *
     * The usage can be one of: sig, enc
     *
     * @param string $use the allowed usage
     * @return void
     */
    public function setUse(string $use);

    /**
     * Returns the allowed operations for the key
     *
     * @return array<string> the allowed operations
     */
    public function getOperations(): ?array;

    /**
     * Sets the allowed operations for the key
     *
     * The values can be one or more of: sign, verify, encrypt, decrypt
     * wrapKey, unwrapKey, deriveKey, deriveBits
     *
     * @param array<string> $ops the allowed operations
     * @return void
     */
    public function setOperations(array $ops);

    /**
     * Returns the size of the key, in bits.  The definition of "size"
     * is dependent on the key algorithm.
     *
     * @return int the size of the key in bits
     */
    public function getSize(): int;

    /**
     * Returns the underlying parameters for the key.  The parameters should
     * be consistent with the way they are specified as a JWK.
     *
     * @return array<string, mixed> the parameters
     */
    public function getKeyData(): array;

    /**
     * Determines whether the key is a public key.
     *
     * A key is public if, and only if, it is an asymmetric key, and the key
     * does not contain any private parameters.
     *
     * @return bool true if the key is public
     */
    public function isPublic(): bool;

    /**
     * Returns the public key.
     *
     * @return KeyInterface|null the public key, or null if the public key
     * does not exist (e.g. is a symmetric key)
     */
    public function getPublicKey(): ?KeyInterface;

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
    public function getThumbnail(): string;
}

?>
