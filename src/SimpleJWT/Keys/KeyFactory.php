<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015
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

use SimpleJWT\Util\ASN1Util;

/**
 * A factory object for creating `Key` objects.
 *
 * This class acts as a central registry to detect the type of a key.  The
 * registry contains three components:
 *
 * - {@link $jwk_kty_map} - a mapping between JWK `kty` values and the PHP
 *   class representing the key
 * - {@link $pem_map} - a mapping between regular expressions for detecting
 *   PEM encoded *private* keys and the PHP class representing the key
 * - {@link $oid_map} - a mapping between object identifiers for detecting
 *   PEM encoded *public* keys and the PHP class representing the key
 *
 */
class KeyFactory {
    static $jwk_kty_map = array(
        RSAKey::KTY => 'SimpleJWT\Keys\RSAKey',
        ECKey::KTY => 'SimpleJWT\Keys\ECKey',
        'oct' => 'SimpleJWT\Keys\OctKey'
    );
    static $pem_map = array(
        RSAKey::PEM_PRIVATE => 'SimpleJWT\Keys\RSAKey',
        ECKey::PEM_PRIVATE => 'SimpleJWT\Keys\ECKey'
    );
    static $oid_map = array(
        RSAKey::OID => 'SimpleJWT\Keys\RSAKey',
        ECKey::EC_OID = 'SimpleJWT\Keys\ECKey'
    );

    /**
     * Detects the format of key data and returns a key object.
     *
     * The supported formats are:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `pem` - the public or private key encoded in PEM (base64 encoded DER) format
     *
     * @param string $data the key data
     * @param string $format the format
     * @return Key the key object
     */
    static public function create($data, $format = null) {
        // 1. Detect format
        if (($format == null) || ($format == 'auto')) {
            if (is_array($data)) {
                $format = 'php';
            } elseif (json_decode($data, true) != null) {
                $format = 'json';
            } elseif (preg_match('/-----([^-:]+)-----/', $data)) {
                $format = 'pem';
            }
        }

        if (($format == null) || ($format == 'auto')) throw new \InvalidArgumentException('Cannot detect key format');

        // 2. Decode JSON
        if ($format == 'json') {
            $data = json_decode($data, true);
            $format = 'php';
        }

        // 3. PHP/JSON
        if ($format == 'php') {
            if (($data != null) && isset($data['kty'])) {
                if (isset(self::$jwk_kty_map[$data['kty']])) {
                    return new self::$jwk_kty_map[$data['kty']]($data, 'php');
                }
            }
        }

        // 4. PEM
        if ($format == 'pem') {
            if (preg_match(Key::PEM_PUBLIC, $data, $matches)) {
                $der = base64_decode($matches[1]);
                if ($der === FALSE) throw new \InvalidArgumentException('Cannot read PEM key');

                $offset = 0;

                $offset += ASN1Util::readDER($der, $offset, $value);  // SEQUENCE
                $offset += ASN1Util::readDER($der, $offset, $value);  // SEQUENCE
                $offset += ASN1Util::readDER($der, $offset, $algorithm);  // OBJECT IDENTIFIER - AlgorithmIdentifier

                $oid = ASN1Util::decodeOID($algorithm);
                if (isset(self::$oid_map[$oid])) {
                    return new self::$oid_map[$oid]($data, 'pem');
                }
            } else {
                foreach (self::$pem_map as $regex => $cls) {
                    if (preg_match($regex, $data)) {
                        return new $cls($data, 'pem');
                    }
                }
            }
        }

        return null;
    }
}

?>
