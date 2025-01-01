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

namespace SimpleJWT\Crypt;

/**
 * A factory object for creating `Algorithm` objects.
 *
 * This class acts as a central registry to provide algorithms.  The
 * registry is stored in {@link $alg_map}, a mapping between regular expressions
 * for detecting `alg` and `enc` parameters and the PHP class representing the
 * algorithm
 *
 */
class AlgorithmFactory {
    /** @var array<string, string> $alg_map */
    static $alg_map = [
        // Signature algorithms
        '/^EdDSA$/' => 'SimpleJWT\Crypt\Signature\EdDSA',
        '/^ES\d+$/' => 'SimpleJWT\Crypt\Signature\OpenSSLSig',
        '/^ES256K$/' => 'SimpleJWT\Crypt\Signature\OpenSSLSig',
        '/^RS\d+$/' => 'SimpleJWT\Crypt\Signature\OpenSSLSig',
        '/^HS\d+$/' => 'SimpleJWT\Crypt\Signature\HMAC',

        // Key management algorithms (derivation or encryption)
        '/^dir$/' => 'SimpleJWT\Crypt\KeyManagement\DirectEncryption',
        '/^RSA1_5$/' => 'SimpleJWT\Crypt\KeyManagement\RSAES',
        '/^RSA-OAEP$/' => 'SimpleJWT\Crypt\KeyManagement\RSAES',
        '/^RSA-OAEP-256$/' => 'SimpleJWT\Crypt\KeyManagement\RSAES',
        '/^A\d+KW$/' => 'SimpleJWT\Crypt\KeyManagement\AESKeyWrap',
        '/^A\d+GCMKW$/' => 'SimpleJWT\Crypt\KeyManagement\AESGCMKeyWrap',
        '/^PBES2-HS\d+\\+A\d+KW$/' => 'SimpleJWT\Crypt\KeyManagement\PBES2',
        '/^ECDH-ES$/' => 'SimpleJWT\Crypt\KeyManagement\ECDH',
        '/^ECDH-ES\\+A\d+KW$/' => 'SimpleJWT\Crypt\KeyManagement\ECDH_AESKeyWrap',

        // Content encryption algorithms
        '/^A\d+CBC-HS\d+$/' => 'SimpleJWT\Crypt\Encryption\AESCBC_HMACSHA2',
        '/^A\d+GCM$/' => 'SimpleJWT\Crypt\Encryption\AESGCM'
    ];

    /** @var array<string, string> $use_map */
    private static $use_map = [
        AlgorithmInterface::SIGNATURE_ALGORITHM => 'SimpleJWT\Crypt\Signature\SignatureAlgorithm',
        AlgorithmInterface::ENCRYPTION_ALGORITHM => 'SimpleJWT\Crypt\Encryption\EncryptionAlgorithm',
        AlgorithmInterface::KEY_ALGORITHM => 'SimpleJWT\Crypt\KeyManagement\KeyManagementAlgorithm'
    ];

    /**
     * Creates an algorithm given a specified `alg` or `enc` parameter.
     *
     * @param string $alg the `alg` or `enc` parameter
     * @param string $use the expected use
     * @throws \UnexpectedValueException if the algorithm cannot be created
     * (e.g. if it a required library is not present) or is not of the expected
     * use
     * @return AlgorithmInterface the algorithm
     */
    static public function create(string $alg, ?string $use = null): AlgorithmInterface {
        if (($use != null) && !isset(self::$use_map[$use])) throw new \InvalidArgumentException('Invalid use');

        foreach (self::$alg_map as $regex => $cls) {
            if (preg_match($regex, $alg)) {
                if ($use != null) {
                    $superclass = self::$use_map[$use];

                    if (!is_subclass_of($cls, $superclass, true)) throw new \UnexpectedValueException('Unexpected use for algorithm: ' . $alg);
                }

                $obj = new $cls($alg);
                if (!($obj instanceof AlgorithmInterface)) {
                    throw new \UnexpectedValueException('Class does not implement AlgorithmInterface: ' . $cls);
                }
                return $obj;
            }
        }
        throw new \UnexpectedValueException('Algorithm not supported: ' . $alg);
    }

    /**
     * Returns a list of supported algorithms for a particular use.
     *
     * The uses can be one of the constants in the {@link AlgorithmInterface} class.
     *
     * @param string $use the use
     * @return array<string> an array of algorithms
     */
    static public function getSupportedAlgs(string $use): array {
        $results = [];

        if (!isset(self::$use_map[$use])) throw new \InvalidArgumentException('Invalid use');
        $superclass = self::$use_map[$use];

        $classes = array_unique(array_values(self::$alg_map));
        foreach ($classes as $cls) {
            if (!is_subclass_of($cls, $superclass, true)) continue;

            $obj = new $cls(null);
            if (!($obj instanceof AlgorithmInterface)) {
                throw new \UnexpectedValueException('Class does not implement AlgorithmInterface: ' . $cls);
            }
            $results = array_merge($results, $obj->getSupportedAlgs());
        }

        return $results;
    }

    /**
     * Adds the `none` algorithm to the repository.
     *
     * By default, the `none` algorithm is not included in the repository
     * for security reasons.  However, there may be instances where the
     * `none` algorithm is required (e.g. in non-security sensitive JWTs).
     *
     * @see removeNoneAlg()
     * @return void
     */
    static public function addNoneAlg() {
        self::$alg_map['/^none$/'] = 'SimpleJWT\Crypt\Signature\None';
    }

    /**
     * Removes the `none` algorithm to the repository.
     *
     * @see addNoneAlg()
     * @return void
     */
    static public function removeNoneAlg() {
        if (isset(self::$alg_map['/^none$/'])) unset(self::$alg_map['/^none$/']);
    }
}

?>
