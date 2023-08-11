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

use SimpleJWT\Util\Util;

/**
 * A class representing a public or private key in an octet key pair.
 * Currently this support Edwards curves (Ed25519) adn ECDH X25519
 */
class OKPKey extends Key {
    const KTY = 'OKP';

    /**
     * Creates an octet key.
     *
     * The supported formats are:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `jwe` - Encrypted JSON web key
     * 
     * Note that `pem` base64 encoded DER format is not supported
     *
     * @param string|array<string, mixed> $data the key data
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     */
    public function __construct($data, $format, $password = null, $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
            case 'json':
            case 'jwe':
                parent::__construct($data, $format, $password, $alg);
                break;
            default:
                throw new KeyException('Incorrect format');
        }
    }

    public function getSize() {
        return 8 * strlen(Util::base64url_decode($this->data['x']));
    }

    public function isPublic() {
        return !isset($this->data['d']);
    }

    public function getPublicKey() {
        return new ECKey([
            'kid' => $this->data['kid'],
            'kty' => $this->data['kty'],
            'crv' => $this->data['crv'],
            'x' => $this->data['x']
        ], 'php');
    }

    public function toPEM() {
        throw new KeyException('PEM format is not supported for OKP keys');
    }

    /**
     * Returns the key in the format used by libsodium
     *
     * @return string the key in Sodium format
     * @throws KeyException if the key cannot be converted
     */
    public function toSodium() {
        if ($this->isPublic()) {
            return Util::base64url_decode($this->data['x']);
        } else {
            switch ($this->data['crv']) {
                case 'Ed25519':
                    return sodium_crypto_sign_keypair_from_secretkey_and_publickey(
                        Util::base64url_decode($this->data['d']),
                        Util::base64url_decode($this->data['x'])
                    );
                case 'X25519':
                    return sodium_crypto_box_keypair_from_secretkey_and_publickey(
                        Util::base64url_decode($this->data['d']),
                        Util::base64url_decode($this->data['x'])
                    );
            }
        }
    }

    /**
     * Gets the subtype for the key.  The subtype is specified in
     * the `crv` parameter.
     * 
     * @return string the subtype
     */
    public function getCurve() {
        return $this->data['crv'];
    }

    protected function getThumbnailMembers() {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['crv', 'kty', 'd', 'x'];
    }
}
?>