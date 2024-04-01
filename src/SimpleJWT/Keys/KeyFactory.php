<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2024
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

use \JsonException;
use SimpleJWT\JWE;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Util\ASN1\DER;
use SimpleJWT\Util\CBOR\CBOR;
use SimpleJWT\Util\CBOR\DataItem as CBORItem;
use SimpleJWT\Util\CBOR\CBORException;

/**
 * A factory object for creating `KeyInterface` objects.
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
    /** @var array<string, string> $jwk_kty_map */
    static $jwk_kty_map = [
        RSAKey::KTY => 'SimpleJWT\Keys\RSAKey',
        ECKey::KTY => 'SimpleJWT\Keys\ECKey',
        OKPKey::KTY => 'SimpleJWT\Keys\OKPKey',
        SymmetricKey::KTY => 'SimpleJWT\Keys\SymmetricKey'
    ];

    /** @var array<string, string> $pem_map */
    static $pem_map = [
        RSAKey::PEM_PRIVATE => 'SimpleJWT\Keys\RSAKey',
        ECKey::PEM_RFC5915_PRIVATE => 'SimpleJWT\Keys\ECKey'
    ];

    /** @var array<string, string> $oid_map */
    static $oid_map = [
        RSAKey::OID => 'SimpleJWT\Keys\RSAKey',
        ECKey::EC_OID => 'SimpleJWT\Keys\ECKey'
    ];

    /** @var array<int, string> $cose_map */
    static $cose_map = [
        RSAKey::COSE_KTY => 'SimpleJWT\Keys\RSAKey',
        ECKey::COSE_KTY => 'SimpleJWT\Keys\ECKey',
        OKPKey::COSE_KTY => 'SimpleJWT\Keys\OKPKey',
        SymmetricKey::COSE_KTY => 'SimpleJWT\Keys\SymmetricKey'
    ];

    /**
     * Detects the format of key data and returns a key object.
     *
     * The supported formats are:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `pem` - the public or private key encoded in PEM (base64 encoded DER) format
     * - `jwe` - Encrypted JSON web key
     *
     * @param string|array<string, mixed> $data the key data
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     * @return KeyInterface the key object
     * @throws KeyException if an error occurs in reading the data
     */
    static public function create($data, string $format = null, ?string $password = null, ?string $alg = 'PBES2-HS256+A128KW') {
        $cbor = new CBOR();
        $cbor_item = null;

        // 1. Detect format
        if (($format == null) || ($format == 'auto')) {
            if (is_array($data)) {
                $format = 'php';
            } elseif (json_decode($data, true) != null) {
                $format = 'json';
            } elseif (substr_count($data, '.') == 5) {
                $format = 'jwe';
            } elseif (preg_match('/-----([^-:]+)-----/', $data)) {
                $format = 'pem';
            } else {
                try {
                    /** @var string $data */
                    $cbor_item = $cbor->decode($data, CBORItem::DECODE_CONVERT_BSTR);
                    if (is_array($cbor_item)) $format = 'cbor';
                } catch (\Exception $e) {}
            }
        }

        if (($format == null) || ($format == 'auto')) throw new KeyException('Cannot detect key format');

        // 2. Decode JSON into PHP array
        if ($format == 'json') {
            try {
                /** @var string $data */
                $json = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
                if (isset($json['ciphertext'])) {
                    $format = 'jwe';
                } else {
                    $data = $json;
                    $format = 'php';
                }
            } catch (JsonException $e) {
                throw new KeyException('Incorrect key data format - malformed JSON', 0, $e);
            }
        }

        // 3. JWE
        if ($format == 'jwe') {
            if ($password == null) {
                throw new KeyException('No password for encrypted key');
            } else {
                $keys = KeySet::createFromSecret($password, 'bin');
                try {
                    $jwe = JWE::decrypt($data, $keys, $alg);
                    $data = json_decode($jwe->getPlaintext());
                    $format = 'php';
                } catch (CryptException $e) {
                    throw new KeyException('Cannot decrypt key', 0, $e);
                }
            }
        }

        // 4. PHP/JSON
        if ($format == 'php') {
            if ($data != null) {
                if (isset($data['kty'])) {
                    if (isset(self::$jwk_kty_map[$data['kty']])) {
                        /** @var KeyInterface $key */
                        $key = new self::$jwk_kty_map[$data['kty']]($data, 'php');
                        return $key;
                    }
                } elseif (isset($data['keys']) && is_array($data['keys'])) {
                    throw new KeyException('Cannot import key set as a single key');
                }
            }
        }

        // 5. Decode CBOR into PHP array
        if ($format == 'cbor') {
            try {
                if ($cbor_item == null) $cbor_item = $cbor->decode($data, CBORItem::DECODE_CONVERT_BSTR);
                // Key attribute 1 = 'kty'
                if (isset(self::$cose_map[$cbor_item[1]])) {
                    /** @var KeyInterface $key */
                    $key = new self::$cose_map[$cbor_item[1]]($cbor_item, 'cbor');
                    return $key;
                }
            } catch (CBORException $e) {
                throw new KeyException('Cannot decode CBOR key', 0, $e);
            }
        }

        // 6. PEM
        if ($format == 'pem') {
            $der = new DER();

            if (preg_match(Key::PEM_PUBLIC, $data, $matches)) {
                /** @var string $binary */
                $binary = base64_decode($matches[1]);
                if ($binary == FALSE) throw new KeyException('Cannot read PEM key');

                $seq = $der->decode($binary);

                $offset = 0;

                $oid = $seq->getChildAt(0)->getChildAt(0)->getValue();
                if (isset(self::$oid_map[$oid])) {
                    /** @var KeyInterface $key */
                    $key = new self::$oid_map[$oid]($data, 'pem');
                    return $key;
                }
            } elseif (preg_match(Key::PEM_PKCS8_PRIVATE, $data, $matches)) {
                /** @var string $binary */
                $binary = base64_decode($matches[1]);
                if ($binary == FALSE) throw new KeyException('Cannot read PEM key');

                $seq = $der->decode($binary);

                $version = $seq->getChildAt(0)->getValue();
                if ($version != 0) throw new KeyException('Invalid private key version: ' . $version);
                
                $oid = $seq->getChildAt(1)->getChildAt(0)->getValue();
                if (isset(self::$oid_map[$oid])) {
                    /** @var KeyInterface $key */
                    $key = new self::$oid_map[$oid]($data, 'pem');
                    return $key;
                }
            } else {
                foreach (self::$pem_map as $regex => $cls) {
                    if (preg_match($regex, $data)) {
                        /** @var KeyInterface $key */
                        $key = new $cls($data, 'pem');
                        return $key;
                    }
                }

                throw new KeyException('PEM key format not supported');
            }
        }

        // 7. Symmetric key
        if (($format == 'base64url') || ($format == 'base64') || ($format == 'bin')) {
            return new SymmetricKey($data, $format);
        }

        throw new KeyException('Invalid key format');
    }
}

?>
