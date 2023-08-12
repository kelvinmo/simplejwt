<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2023
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
 * Interface for keys which can be used for ECDH-ES
 */
interface ECDHKeyInterface extends KeyInterface {
    /**
     * Gets the name of the curve for the key.  This is usually specified in
     * the `crv` parameter.
     * 
     * @return string the curve name
     */
    public function getCurve(): string;

    /**
     * Checks whether another key is on the same curve as this key.
     * 
     * @param ECDHKeyInterface $public_key the public key to check
     * @return bool true if the key is on the same curve
     * @see https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/
     */
    public function isOnSameCurve(ECDHKeyInterface $public_key): bool;

    /**
     * Derived a shared key based on a supplied public key.
     * 
     * This method can only be called if $this is a private key.
     * 
     * @param ECDHKeyInterface $public_key the public key
     * @return string the shared key
     */
    public function deriveAgreementKey(ECDHKeyInterface $public_key): string;

    /**
     * Creates an ephemeral keypair using the same curve as this key
     * 
     * @return ECDHKeyInterface the ephemeral keypair
     */
    public function createEphemeralKey(): ECDHKeyInterface;
}

?>
