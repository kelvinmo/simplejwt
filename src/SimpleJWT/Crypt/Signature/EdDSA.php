<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2023
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

use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Keys\Key;
use SimpleJWT\Keys\OKPKey;
use SimpleJWT\Keys\KeyException;
use SimpleJWT\Util\Util;

/**
 * Abstract class for SHA2-based signature algorithms.
 */
class EdDSA extends BaseAlgorithm implements SignatureAlgorithm {
    public function __construct($alg) {
        parent::__construct($alg);
    }

    public function getKeyCriteria() {
        return ['kty' => 'OKP', 'crv' => 'Ed25519', '@use' => 'sig', '@key_ops' => ['sign', 'verify']];
    }

    public function getSupportedAlgs() {
        if (function_exists('sodium_crypto_sign_detached')) {
            return ['EdDSA'];
        }
        return [];
    }

    public function sign($data, $keys, $kid = null) {
        $key = $this->getSigningKey($keys, $kid);
        if (($key == null) || !($key instanceof OKPKey)) {
            throw new KeyException('Key not found or is invalid');
        }
        /** @var non-empty-string $key_pair */
        $key_pair = $key->toSodium();
        $secret_key = sodium_crypto_sign_secretkey($key_pair);

        $binary = sodium_crypto_sign_detached($data, $secret_key);
        return Util::base64url_encode($binary);
    }

    public function verify($signature, $data, $keys, $kid = null) {
        $key = $this->selectKey($keys, $kid, [Key::PUBLIC_PROPERTY => true, '~use' => 'sig']);
        if (($key == null) || !($key instanceof OKPKey)) {
            throw new KeyException('Key not found or is invalid');
        }

        /** @var non-empty-string $binary */
        $binary = Util::base64url_decode($signature);
        /** @var non-empty-string $public_key */
        $public_key = $key->toSodium();

        return sodium_crypto_sign_verify_detached($binary, $data, $public_key);
    }


    public function getSigningKey($keys, $kid = null) {
        return $this->selectKey($keys, $kid, [Key::PUBLIC_PROPERTY => false]);
    }

    public function shortHash($data) {
        // EdDSA uses SHA-512
        // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1
        $hash = hash('sha512', $data, true);
        $short = substr($hash, 0, 32);
        return Util::base64url_encode($short);
    }
}

?>
