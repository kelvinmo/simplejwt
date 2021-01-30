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

namespace SimpleJWT\Keys;

use SimpleJWT\Util\Util;

/**
 * Class representing a symmetric key
 */
class SymmetricKey extends Key {
    const KTY = 'oct';

    /**
     * Creates a symmetric key.
     *
     * The supported formats are:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `jwe` - Encrypted JSON web key
     * - `base64url` - the symmetric key encoded in Base64url format
     * - `base64` - the symmetric key encoded in Base64 format
     * - `bin` - the symmetric key encoded in binary format
     *
     * @param string|array $data the key data
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
            case 'base64url':
                $jwk = [
                    'kty' => self::KTY,
                    'k' => $data
                ];
                parent::__construct($jwk);
                break;
            case 'base64':
                $jwk = [
                    'kty' => self::KTY,
                    'k' => Util::base64url_encode(base64_decode($data))
                ];
                parent::__construct($jwk);
                break;
            case 'bin':
                $jwk = [
                    'kty' => self::KTY,
                    'k' => Util::base64url_encode($data)
                ];
                parent::__construct($jwk);
                break;
            default:
                throw new KeyException('Incorrect format');
        }

        if (!isset($this->data['kty'])) $this->data['kty'] = self::KTY;
    }

    public function getSize() {
        return 8 * strlen($this->toBinary());
    }

    public function isPublic() {
        return false;
    }

    public function getPublicKey() {
        return null;
    }

    public function toPEM() {
        throw new KeyException('Unsupported key format');
    }

    /**
     * Returns the symmetric key in binary representation
     *
     * @return string the key
     */
    public function toBinary() {
        return Util::base64url_decode($this->data['k']);
    }

    protected function getThumbnailMembers() {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        return ['k', 'kty'];
    }
}

?>
