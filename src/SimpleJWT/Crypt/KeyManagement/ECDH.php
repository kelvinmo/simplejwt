<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2020-2024
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

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Crypt\AlgorithmInterface;
use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Keys\ECDHKeyInterface;
use SimpleJWT\Keys\KeyFactory;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util;

/**
 * Implementation of the Elliptic Curve Diffie-Hellman 
 * Ephemeral Static algorithm.
 * 
 * @see https://tools.ietf.org/html/rfc7518#section-4.6
 */
class ECDH extends BaseAlgorithm implements KeyDerivationAlgorithm {
    /** @var int $key_size */
    private $key_size;

    /**
     * Creates an ECDH algorithm.
     *
     * This algorithm can be used directly to generate a content encryption key,
     * or as an intermediate step to create a key to wrap the content
     * encryption key (using a key wrapping algorithm).
     * 
     * Where an underlying algorithm is used, the size of the derived key needs
     * to be specified in the $key_size parameter.
     *
     * @param string $alg the algorithm, either `null` or the string `ECDH-ES`
     * @param int $key_size the required size of the derived key in bits
     * @throws \UnexpectedValueException if the `$alg` parameter is not supported
     * by this class
     */
    public function __construct(?string $alg, ?int $key_size = null) {
        parent::__construct($alg);
        $this->key_size = $key_size;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAlgs(): array {
        if (defined('OPENSSL_KEYTYPE_EC') && function_exists('openssl_pkey_derive')) {
            // openssl_pkey_derive is made available from PHP 7.3?
            return ['ECDH-ES'];
        } else {
            // Not supported
            return [];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyCriteria(): array {
        return ['kty' => ['EC', 'OKP'], '@use' => 'enc', '@key_ops' => 'deriveKey'];
    }

    /**
     * {@inheritdoc}
     */
    public function deriveKey(KeySet $keys, array &$headers, ?string $kid = null): string {
        /** @var ECDHKeyInterface $key */
        $key = $this->selectKey($keys, $kid);
        if ($key == null) {
            throw new CryptException('Key not found or is invalid', CryptException::KEY_NOT_FOUND_ERROR);
        }

        // 1. Get the required key length and alg input into Concat KDF
        if (isset($headers['enc'])) {
            try {
                /** @var \SimpleJWT\Crypt\Encryption\EncryptionAlgorithm $enc */
                $enc = AlgorithmFactory::create($headers['enc'], AlgorithmInterface::ENCRYPTION_ALGORITHM);
                $size = $enc->getCEKSize();
            } catch (\UnexpectedValueException $e) {
                throw new CryptException('Unexpected enc algorithm', CryptException::INVALID_DATA_ERROR, $e);
            }
        } elseif ($this->key_size != null) {
            $size = $this->key_size;
        } else {
            throw new CryptException('Key size not specified', CryptException::INVALID_DATA_ERROR);
        }

        if ($this->getAlg() == 'ECDH-ES') {
            $alg = $headers['enc'];
        } else {
            $alg = $this->getAlg();
        }

        // 2. If 'epk' header is present, check the ephemeral public key for compatibility
        //    against (our) private key specified in $key
        //
        //    Otherwise, generate the ephemeral public key based on the recipient's public
        //    key specified in $key
        if (isset($headers['epk'])) {
            // (a) Load the ephemeral public key
            $ephemeral_public_key = KeyFactory::create($headers['epk'], 'php');
            if (!($ephemeral_public_key instanceof ECDHKeyInterface)) {
                throw new CryptException("Invalid epk: not an ECDH compatible key", CryptException::INVALID_DATA_ERROR);
            }

            // (b) Check that $key is a private key
            if ($key->isPublic()) {
                throw new CryptException('Key is a public key; private key expected', CryptException::INVALID_DATA_ERROR);
            }

            // (c) Check whether the epk is on the private key's curve to mitigate
            // against invalid curve attacks
            if (!$key->isOnSameCurve($ephemeral_public_key)) {
                throw new CryptException('Invalid epk: incompatible curve', CryptException::INVALID_DATA_ERROR);
            }

            // (d) Set the ECDH keys
            $dh_public_key = $ephemeral_public_key;
            $dh_private_key = $key;
        } else {
            // (a) Check that $key is a public key (i.e. the recipient's)
            if (!$key->isPublic()) {
                throw new CryptException('Key is a private key; public key expected', CryptException::INVALID_DATA_ERROR);
            }

            // (b) Create an ephemeral key pair with the same curve as the recipient's public
            //     key, then set the epk header
            $ephemeral_private_key = $key->createEphemeralKey();
            $ephemeral_public_key = $ephemeral_private_key->getPublicKey();
            $headers['epk'] = $ephemeral_public_key->getKeyData();

            // (c) Set the ECDH keys
            $dh_public_key = $key;
            $dh_private_key = $ephemeral_private_key;
        }

        // 3. Calculate agreement key (Z)
        $Z = $dh_private_key->deriveAgreementKey($dh_public_key);
        
        // 4. Derive key from Concat KDF
        $apu = (isset($headers['apu'])) ? $headers['apu'] : '';
        $apv = (isset($headers['apv'])) ? $headers['apv'] : '';
        return $this->concatKDF($Z, $alg, $size, $apu, $apv);
    }

    /**
     * Derives a key using the Concat KDF.
     * 
     * The KDF is defined in section 5.8.1 (Single-step Key-Derivation Function)
     * of NIST publication 800-56A.
     * 
     * @param string $Z the shared secret as a binary string
     * @param string $alg the enc or alg value
     * @param int $size the size of the output, in bits
     * @param string $apu the Part U value as a base64url encoded string
     * @param string $apv the Part V value as a base64url encoded string
     * @return string the derived key as a binary string
     * @see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
     */
    final protected function concatKDF(string $Z, string $alg, int $size, string $apu = '', string $apv = ''): string {
        $apu = ($apu == null) ? '' : Util::base64url_decode($apu);
        $apv = ($apv == null) ? '' : Util::base64url_decode($apv);

        $input = pack('N', 1)
            . $Z
            . pack('N', strlen($alg)) . $alg
            . pack('N', strlen($apu)) . $apu
            . pack('N', strlen($apv)) . $apv
            . pack('N', $size);
        
        return substr(hash('sha256', $input, true), 0, $size / 8);
    }
}

?>