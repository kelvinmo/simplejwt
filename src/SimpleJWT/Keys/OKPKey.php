<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2023-2025
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

use \SodiumException;
use SimpleJWT\Util\Util;

/**
 * A class representing a public or private key in an octet key pair.
 * Currently this support Edwards curves (Ed25519) adn ECDH X25519
 */
class OKPKey extends Key implements ECDHKeyInterface {
    const KTY = 'OKP';
    const COSE_KTY = 1;

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
    public function __construct($data, string $format, ?string $password = null, ?string $alg = 'PBES2-HS256+A128KW') {
        switch ($format) {
            case 'php':
            case 'json':
            case 'jwe':
                parent::__construct($data, $format, $password, $alg);
                break;
            case 'cbor':
                parent::__construct($data, $format, $password, $alg);
                if ($this->data['kty'] != self::COSE_KTY) throw new KeyException('Incorrect CBOR key type', KeyException::INVALID_KEY_ERROR);
                $this->data['kty'] = self::KTY;
                $this->replaceDataKeys([ -1 => 'crv', -2 => 'x', -4 => 'd' ]);
                $this->replaceDataValues('crv', [ 4 => 'X25519', 6 => 'Ed25519' ]);
                break;
            default:
                throw new KeyException('Incorrect format', KeyException::INVALID_KEY_ERROR);
        }
    }

    public function getSize(): int {
        return 8 * strlen(Util::base64url_decode($this->data['x']));
    }

    public function isPublic(): bool {
        return !isset($this->data['d']);
    }

    public function isOnSameCurve($public_key): bool {
        if (!($public_key instanceof OKPKey)) return false;
        if (!Util::secure_compare($this->data['crv'], $public_key->data['crv'])) return false;
        if (!Util::secure_compare($this->data['crv'], 'X25519')) return false;

        return true;
    }

    public function getPublicKey(): ?KeyInterface {
        $data = [
            'kty' => $this->data['kty'],
            'crv' => $this->data['crv'],
            'x' => $this->data['x']
        ];
        if (isset($this->data['kid'])) $data['kid'] = $this->data['kid'];
        return new OKPKey($data, 'php');
    }

    /**
     * Returns the key in the format used by libsodium
     *
     * @return string the key in Sodium format
     * @throws KeyException if the key cannot be converted
     */
    public function toSodium(): string {
        if ($this->isPublic()) {
            return Util::base64url_decode($this->data['x']);
        } else {
            $d = Util::base64url_decode($this->data['d']);
            $x = Util::base64url_decode($this->data['x']);
            if ((strlen($d) == 0) || strlen($x) == 0) {
                throw new KeyException('Invalid key data', KeyException::INVALID_KEY_ERROR);
            }

            try {
                switch ($this->data['crv']) {
                    case 'Ed25519':
                        return sodium_crypto_sign_keypair_from_secretkey_and_publickey($d . $x, $x);
                    case 'X25519':
                        return sodium_crypto_box_keypair_from_secretkey_and_publickey($d, $x);
                    default:
                        throw new KeyException('Cannot convert to Sodium format', KeyException::INVALID_KEY_ERROR);
                }
            } catch (SodiumException $e) {
                throw new KeyException('Cannot convert to Sodium format: ' . $e->getMessage(), KeyException::SYSTEM_LIBRARY_ERROR, $e);
            }
        }
    }

    /**
     * Gets the subtype for the key.  The subtype is specified in
     * the `crv` parameter.
     * 
     * @return string the subtype
     */
    public function getCurve(): string {
        return $this->data['crv'];
    }

    /**
     * {@inheritdoc}
     */
    public function createEphemeralKey(): ECDHKeyInterface {
        $crv = $this->getCurve();
        if ($crv != 'X25519') throw new \InvalidArgumentException('Curve not found');

        try {
            $key = sodium_crypto_box_keypair();
            $d = sodium_crypto_box_secretkey($key);
            $x = sodium_crypto_box_publickey($key);
    
            return new OKPKey([
                'kty' => 'OKP',
                'crv' => 'X25519',
                'd' => Util::base64url_encode($d),
                'x' => Util::base64url_encode($x)
            ], 'php');
        } catch (SodiumException $e) {
            throw new KeyException('Cannot create ephemeral key: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function deriveAgreementKey(ECDHKeyInterface $public_key): string {
        assert(function_exists('sodium_crypto_scalarmult'));

        if (!($public_key instanceof OKPKey)) throw new KeyException('Key type does not match', KeyException::INVALID_KEY_ERROR);
        if ($this->isPublic() || !$public_key->isPublic()) throw new KeyException('Parameter is not a public key', KeyException::INVALID_KEY_ERROR);

        $public_key = Util::base64url_decode($public_key->data['x']);
        $secret_key = Util::base64url_decode($this->data['d']);

        try {
            $result = sodium_crypto_scalarmult($secret_key, $public_key);
            if (strlen($result) != 32) throw new KeyException('Key agreement error', KeyException::SYSTEM_LIBRARY_ERROR);
            return $result;
        } catch (SodiumException $e) {
            throw new KeyException('Cannot derive agreement key: ' . $e->getMessage(), KeyException::SYSTEM_LIBRARY_ERROR, $e);
        }
    }

    protected function getThumbnailMembers(): array {
        // https://datatracker.ietf.org/doc/html/rfc8037#section-2
        return ['crv', 'kty', 'x'];
    }
}
?>