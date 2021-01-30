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

namespace SimpleJWT\Util;

use SimpleJWT\JWT;
use SimpleJWT\JWE;
use SimpleJWT\InvalidTokenException;

/**
 * A helper class for detecting JWTs and JWEs in various serialisation
 * formats.  This class is particularly useful in situations where both
 * JWTs and JWEs are accepted.
 */
class Helper {

    const COMPACT_FORMAT = 'compact';
    const JSON_FORMAT = 'json';


    private $data;
    private $type;
    private $format;

    /**
     * Creates an instance of Helper with specified encoded data.
     * This calls the {@link detect()} function to detect the format of
     * the encoded data.
     *
     * @param string $data an encoded JWT or JWE
     * @throw InvalidTokenException if the encoded data is invalid
     */
    function __construct($data) {
        $results = self::detect($data);

        if ($results == null) {
            throw new InvalidTokenException('Cannot parse format', InvalidTokenException::TOKEN_PARSE_ERROR);
        }

        $this->data = $data;
        $this->type = $results['type'];
        $this->format = $results['format'];
    }

    /**
     * Returns the type of the encoded data.
     *
     * @return string either `JWT` or `JWE`
     */
    function getType() {
        return $this->type;
    }

    /**
     * Returns the serialisation format used to encode the data.
     *
     * @return string either `compact` or `json`
     */
    function getFormat() {
        return $this->format;
    }

    /**
     * Decrypts or verifies the signature of the token and returns
     * the SimpleJWT object representing the token.
     *
     * @param SimpleJWT\Keys\KeySet $keys the key set containing the decryption or
     * verification keys
     * @param string $expected_alg the expected value of the `alg` parameter, which
     * should be agreed between the parties out-of-band
     * @param string $kid the ID of the key to use for decryption or verification. If null, this
     * is automatically retrieved
     * @return JWT|JWE the decoded JWT or JWE
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    function getObject($keys, $expected_alg, $kid = null) {
        switch ($this->type) {
            case 'JWT':
                return JWT::decode($this->data, $keys, $expected_alg, $kid, [], $this->format);
            case 'JWE':
                return JWE::decrypt($this->data, $keys, $expected_alg, $kid, $this->format);
        }
    }

    /**
     * Decrypts and verifies a nested JWT.
     *
     * If the supplied token is a JWT, this function calls {@link getObject()}
     * to decode the JWT.
     *
     * If the supplied token is a JWE, the JWE is firstly decrypted, then the underlying
     * plaintext is treated as a JWT, and further decoded.
     *
     * @param SimpleJWT\Keys\KeySet $keys the key set containing the decryption
     * and verification keys
     * @param string $expected_jwe_alg the expected value of the `alg` parameter for the
     * JWE, which should be agreed between the parties out-of-band
     * @param string $expected_jwt_alg the expected value of the `alg` parameter for the
     * underlying JWT, which should be agreed between the parties out-of-band
     * @param string $jwe_kid the ID of the key to use for decryption. If null, this
     * is automatically retrieved
     * @param string $jwt_kid the ID of the key to use for verification. If null, this
     * is automatically retrieved
     * @return JWT the decoded JWT
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    function getJWTObject($keys, $expected_jwe_alg, $expected_jwt_alg, $jwe_kid = null, $jwt_kid = null) {
        switch ($this->type) {
            case 'JWT':
                return $this->getObject($keys, $expected_jwt_alg, $jwt_kid);
            case 'JWE':
                $jwe = JWE::decrypt($this->data, $keys, $expected_jwe_alg, $jwe_kid, $this->format);
                if ($jwe->getHeader('cty') != 'JWT') {
                    throw new InvalidTokenException('Not a nested JWT', InvalidTokenException::TOKEN_PARSE_ERROR);
                }
                return JWT::decode($jwe->getPlaintext(), $keys, $expected_jwt_alg, $jwt_kid);
        }
    }

    /**
     * Attempts to detect the format of JWT or JWE encoded data.
     *
     * @param string $data the encoded data
     * @return mixed an array with keys `type` and `format`
     * (see {@link getType()} and {@link getFormat()}), or `null`
     * if the format cannot be detected
     */
    static function detect($data) {
        $results = [];

        $obj = json_decode($data, true);

        if ($obj == null) {
            $dot_count = substr_count($data, '.');
            if ($dot_count == 2) {
                $results['type'] = 'JWT';
                $results['format'] = self::COMPACT_FORMAT;
            } elseif ($dot_count == 4) {
                $results['type'] = 'JWE';
                $results['format'] = self::COMPACT_FORMAT;
            }
        } else {
            if (isset($obj['signature']) || isset($obj['signatures'])) {
                $results['type'] = 'JWT';
                $results['format'] = self::JSON_FORMAT;
            } elseif (isset($obj['ciphertext'])) {
                $results['type'] = 'JWE';
                $results['format'] = self::JSON_FORMAT;
            }
        }

        return (isset($results['type'])) ? $results : null;
    }
}

?>
