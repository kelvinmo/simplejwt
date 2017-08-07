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

namespace SimpleJWT;

use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Crypt\CryptException;
use SimpleJWT\Keys\KeyException;
use SimpleJWT\Util\Util;

/**
 * A JSON web token (JWT) with a signature.
 *
 * A JWT consists of a header and a set of claims.  To create a JWT, use the
 * constructor with the header and claims as the parameter.  The JWT can then
 * be signed and serialised using the {@link encode()} function.
 *
 * To decode a serialised JWT, use the {@link decode()} static function.  If
 * successful, the static function will return a JWT object.  The headers and
 * claims can then be retrieved using the {@link getHeaders()} and {@link getClaims()}
 * functions.
 */
class JWT {
    const COMPACT_FORMAT = 'compact';
    const JSON_FORMAT = 'json';

    static public $TIME_ALLOWANCE = 300;

    protected $headers = array(
        'typ' => 'JWT',
        'alg' => 'RS256'
    );

    protected $claims = array();

    /**
     * Creates a new JWT.
     *
     * @param array $headers the headers
     * @param array $claims the claims
     */
    public function __construct($headers, $claims) {
        $this->headers = $headers;
        $this->claims = $claims;
    }

    /**
     * Decodes a serialised JWT.
     *
     * @param string $token the serialised JWT
     * @param \SimpleJWT\Keys\KeySet $keys the key set containing the key to verify the
     * JWT's signature
     * @param string $expected_alg the expected value of the `alg` parameter, which
     * should be agreed between the parties out-of-band
     * @param string $kid the ID of the key to use to verify the signature. If null, this
     * is automatically retrieved
     * @param bool|array $skip_validation an array of headers or claims that
     * should be ignored as part of the validation process (e.g. if expired tokens
     * are to be accepted), or false if all validation
     * is to be performed.
     * @param string $format the JWT serialisation format
     * @return JWT the decoded JWT
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    public static function decode($token, $keys, $expected_alg, $kid = null, $skip_validation = array(), $format = self::COMPACT_FORMAT) {
        if ($skip_validation === false) $skip_validation = array();

        switch ($format) {
            case self::COMPACT_FORMAT:
                $parts = explode('.', $token, 3);
                if (count($parts) != 3) throw new InvalidTokenException('Cannot decode compact serialisation', InvalidTokenException::TOKEN_PARSE_ERROR);
                list($protected, $payload, $signature) = $parts;
                break;
            case self::JSON_FORMAT:
                $obj = json_decode($token, true);
                if ($obj == null) throw new InvalidTokenException('Cannot decode JSON', InvalidTokenException::TOKEN_PARSE_ERROR);
                $payload = $obj['payload'];

                if (isset($obj['signatures'])) {
                    foreach ($obj['signatures'] as $signature_obj) {
                        if (isset($signature_obj['header']['kid'])) {
                            $target_kid = $signature_obj['header']['kid'];
                            if (($target_kid == $kid) || ($keys->getById($target_kid) != null)) {
                                $unprotected = $signature_obj['header'];
                                $protected = $signature_obj['protected'];
                                $signature = $signature_obj['signature'];
                                break;
                            }
                        }
                        throw new InvalidTokenException('Cannot find verifiable signature', InvalidTokenException::TOKEN_PARSE_ERROR);
                    }
                } else {
                    $unprotected = $obj['header'];
                    $protected = $obj['protected'];
                    $signature = $obj['signature'];
                }
                break;
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }

        $headers = json_decode(Util::base64url_decode($protected), true);
        if ($headers == null) throw new InvalidTokenException('Cannot decode header', InvalidTokenException::TOKEN_PARSE_ERROR);

        // Process crit
        if (isset($headers['crit'])) {
            foreach ($headers['crit'] as $critical) {
                if (!in_array($critical, array('nbf', 'exp', 'alg', 'kid'))) {
                    throw new InvalidTokenException('Critical header not supported: ' . $critical, InvalidTokenException::UNSUPPORTED_ERROR);
                }
            }
        }

        if (isset($unprotected)) $headers = array_merge($headers, $unprotected);

        $claims = json_decode(Util::base64url_decode($payload), true);
        if ($claims == null) throw new InvalidTokenException('Cannot decode claims', InvalidTokenException::TOKEN_PARSE_ERROR);

        // Check signatures
        if ($headers['alg'] != $expected_alg) throw new InvalidTokenException('Unexpected algorithm', InvalidTokenException::SIGNATURE_VERIFICATION_ERROR);
        $signer = AlgorithmFactory::create($expected_alg);
        $signing_input = $protected . '.' . $payload;

        try {
            if (isset($headers['kid'])) $kid = $headers['kid'];
            $result = $signer->verify($signature, $signing_input, $keys, $kid);
        } catch (KeyException $e) {
            throw new InvalidTokenException($e->getMessage(), InvalidTokenException::SIGNATURE_VERIFICATION_ERROR, $e);
        } catch (CryptException $e) {
            throw new InvalidTokenException($e->getMessage(), InvalidTokenException::SIGNATURE_VERIFICATION_ERROR, $e);
        }

        if (!$result) throw new InvalidTokenException('Incorrect signature', InvalidTokenException::SIGNATURE_VERIFICATION_ERROR);

        // Check time, etc
        $time = time();
        if (isset($claims['nbf']) && !in_array('nbf', $skip_validation)) {
            if ($time < $claims['nbf'] - self::$TIME_ALLOWANCE) throw new InvalidTokenException('Too early due to nbf claim', InvalidTokenException::TOO_EARLY_ERROR, null, $claims['nbf']);
        }

        if (isset($claims['exp']) && !in_array('exp', $skip_validation)) {
            if ($time > $claims['exp'] + self::$TIME_ALLOWANCE) throw new InvalidTokenException('Too late due to exp claim', InvalidTokenException::TOO_LATE_ERROR, null, $claims['exp']);
        }

        return new JWT($headers, $claims);
    }

    /**
     * Returns the JWT's headers.
     *
     * @return array the headers
     */
    public function getHeaders() {
        return $this->headers;
    }

    /**
     * Returns a specified header
     *
     * @param string $header the header to return
     * @return mixed the header value
     */
    public function getHeader($header) {
        return $this->headers[$header];
    }

    /**
     * Returns the JWT's claims.
     *
     * @return array the claims
     */
    public function getClaims() {
        return $this->claims;
    }

    /**
     * Returns a specified claim
     *
     * @param string $claim the claim to return
     * @return mixed the claim value
     */
    public function getClaim($claim) {
        return $this->claims[$claim];
    }

    /**
     * Signs and serialises the JWT.
     *
     * @param \SimpleJWT\Keys\KeySet $keys the key set containing the key to sign the
     * JWT
     * @param string $kid the ID of the key to use to sign. If null, this
     * is automatically retrieved
     * @param bool|array $auto_complete an array of headers or claims that
     * should be automatically completed, or false if no auto-completion is
     * to be performed
     * @param string $alg if not null, override the `alg` header
     * @param string $format the JWT serialisation format
     * @return string the signed and serialised JWT
     * @throws \SimpleJWT\Keys\KeyException if there is an error obtaining the key
     * to sign the JWT
     * @throws \SimpleJWT\Crypt\CryptException if there is a cryptographic error
     */
    public function encode($keys, $kid = null, $auto_complete = array('iat', 'kid'), $alg = null, $format = self::COMPACT_FORMAT) {
        if ($auto_complete === false) $auto_complete = array();
        if ($alg != null) $this->headers['alg'] = $alg;
        if (in_array('iat', $auto_complete) && !isset($this->claims['iat'])) $this->claims['iat'] = time();

        try {
            $signer = AlgorithmFactory::create($this->headers['alg']);
        } catch (\UnexpectedValueException $e) {
            throw new CryptException($e->getMessage(), 0, $e);
        }
        $key = $signer->getSigningKey($keys, $kid);
        if (($key != null) && in_array('kid', $auto_complete)) $this->headers['kid'] = $key->getKeyId();
        $protected = Util::base64url_encode(json_encode($this->headers));
        $payload = Util::base64url_encode(json_encode($this->claims));
        $signing_input = $protected . '.' . $payload;
        $signature = $signer->sign($signing_input, $keys, $kid);

        switch ($format) {
            case self::COMPACT_FORMAT:
                return $signing_input . '.' . $signature;
            case self::JSON_FORMAT:
                return json_encode(array(
                    'protected' => $protected,
                    'payload' => $payload,
                    'signature' => $signature
                ));
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }
    }
}
?>
