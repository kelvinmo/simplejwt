<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2022
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
use SimpleJWT\Util\Helper;
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
    /** @var string COMPACT_FORMAT Compact JWT serialisation format */
    const COMPACT_FORMAT = Helper::COMPACT_FORMAT;
    /** @var string JSON_FORMAT JSON JWT serialisation format */
    const JSON_FORMAT = Helper::JSON_FORMAT;

    static public $TIME_ALLOWANCE = 300;

    protected $headers = [
        'typ' => 'JWT',
        'alg' => 'RS256'
    ];

    protected $claims = [];

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
     * @return JWT the decoded JWT
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    public static function decode($token, $keys, $expected_alg, $kid = null, $skip_validation = []) {
        if ($skip_validation === false) $skip_validation = [];

        $headers = [];
        $signing_input = '';
        
        $deserialised = self::deserialise($token);
        $claims = $deserialised['claims'];
        if (count($deserialised['signatures']) > 1) {
            // Multiple signatures, choose one
            foreach ($deserialised['signatures'] as $signature_obj) {
                if (isset($signature_obj['headers']['kid'])) {
                    $target_kid = $signature_obj['headers']['kid'];
                    if (($target_kid == $kid) || ($keys->getById($target_kid) != null)) {
                        $headers = $signature_obj['headers'];
                        $signing_input = $signature_obj['signing_input'];
                        $signature = $signature_obj['signature'];
                        break;
                    }
                }
            }
            if (!isset($signature)) throw new InvalidTokenException('Cannot find verifiable signature', InvalidTokenException::SIGNATURE_VERIFICATION_ERROR);
        } else {
            $headers = $deserialised['signatures'][0]['headers'];
            $signing_input = $deserialised['signatures'][0]['signing_input'];
            $signature = $deserialised['signatures'][0]['signature'];
        }

        // Process crit
        if (isset($headers['crit'])) {
            foreach ($headers['crit'] as $critical) {
                if (!in_array($critical, ['nbf', 'exp', 'alg', 'kid'])) {
                    throw new InvalidTokenException('Critical header not supported: ' . $critical, InvalidTokenException::UNSUPPORTED_ERROR);
                }
            }
        }

        // Check signatures
        if ($headers['alg'] != $expected_alg) throw new InvalidTokenException('Unexpected algorithm', InvalidTokenException::SIGNATURE_VERIFICATION_ERROR);
        /** @var \SimpleJWT\Crypt\SignatureAlgorithm $signer */
        $signer = AlgorithmFactory::create($expected_alg);

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
            if (!is_numeric($claims['nbf'])) throw new InvalidTokenException('nbf claim is not an integer', InvalidTokenException::TOKEN_PARSE_ERROR);
            if ($time < $claims['nbf'] - self::$TIME_ALLOWANCE) throw new InvalidTokenException('Too early due to nbf claim', InvalidTokenException::TOO_EARLY_ERROR, null, $claims['nbf']);
        }

        if (isset($claims['exp']) && !in_array('exp', $skip_validation)) {
            if (!is_numeric($claims['exp'])) throw new InvalidTokenException('exp claim is not an integer', InvalidTokenException::TOKEN_PARSE_ERROR);
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
    public function encode($keys, $kid = null, $auto_complete = ['iat', 'kid'], $alg = null, $format = self::COMPACT_FORMAT) {
        if ($auto_complete === false) $auto_complete = [];
        if ($alg != null) $this->headers['alg'] = $alg;
        if (in_array('iat', $auto_complete) && !isset($this->claims['iat'])) $this->claims['iat'] = time();

        try {
            /** @var \SimpleJWT\Crypt\SignatureAlgorithm $signer */
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
                return json_encode([
                    'protected' => $protected,
                    'payload' => $payload,
                    'signature' => $signature
                ]);
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }
    }
    
    /**
     * Deserialises a JWT without checking its validity.
     *
     * Generally, you should use the {@link decode()} function to decode and
     * verify a JWT.  However, in certain circumstances you do not wish to
     * validate JWT, such as obtaining untrusted &quot;hints&quot; from the
     * claims may be a JWT.  This function provides such a deserialisation
     * mechanism
     * 
     * Note that if the JWT contains multiple signatures, an InvalidTokenException
     * will be thrown.
     *
     * @param string $token the serialised JWT
     * @return array an array containing `claims` (deserialised claims) and
     * `signatures`, an array of arrays each containing `headers` (the
     * deserialised header), `signing_input` (i.e. the first two
     * parts of the serialised JWT) and `signature` (the signature)
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    public static function deserialise($token) {
        $detect_result = Helper::detect($token);
        if ($detect_result == null)
            throw new \InvalidArgumentException('Unrecognised token format');
        $format = $detect_result['format'];

        $result = [];
        $signatures = [];

        switch ($format) {
            case self::COMPACT_FORMAT:
                $parts = explode('.', $token, 3);

                if (count($parts) == 3) {
                    list($protected, $payload, $signature) = $parts;
                } elseif (count($parts) == 2) {
                    list($protected, $payload) = $parts;
                    $signature = '';
                } else {
                    throw new InvalidTokenException('Cannot decode compact serialisation', InvalidTokenException::TOKEN_PARSE_ERROR);
                }
                
                $signatures[] = [ 
                    'unprotected' => [],
                    'protected' => $protected,
                    'signature' => $signature
                ];
                break;
            case self::JSON_FORMAT:
                $obj = json_decode($token, true);
                if ($obj == null) throw new InvalidTokenException('Cannot decode JSON', InvalidTokenException::TOKEN_PARSE_ERROR);
                $payload = $obj['payload'];

                if (isset($obj['signatures'])) {
                    foreach ($obj['signatures'] as $signature_obj) {
                        if (!isset($signature_obj['protected']) || !isset($signature_obj['signature']))
                            throw new InvalidTokenException('Missing protected or signature member', InvalidTokenException::TOKEN_PARSE_ERROR);
                        
                        $signature = [
                            'unprotected' => [],
                            'protected' => $signature_obj['protected'],
                            'signature' => $signature_obj['signature']
                        ];

                        if (isset($signature_obj['header'])) $signature['unprotected'] = $signature_obj['header'];

                        $signatures[] = $signature;
                    }
                } else {
                    if (!isset($obj['protected']) || !isset($obj['signature']))
                        throw new InvalidTokenException('Missing protected or signature member', InvalidTokenException::TOKEN_PARSE_ERROR);

                    $signature = [
                        'unprotected' => [],
                        'protected' => $obj['protected'],
                        'signature' => $obj['signature']
                    ];
                    if (isset($obj['header'])) $signature['unprotected'] = $obj['header'];

                    $signatures[] = $signature;
                }
                break;
            default:
                throw new \InvalidArgumentException('Incorrect format');
        }

        $result['claims'] = json_decode(Util::base64url_decode($payload), true);
        if ($result['claims'] == null) throw new InvalidTokenException('Cannot decode claims', InvalidTokenException::TOKEN_PARSE_ERROR);

        $result['signatures'] = [];
        
        foreach ($signatures as $signature) {
            $headers = json_decode(Util::base64url_decode($signature['protected']), true);
            if ($headers == null) throw new InvalidTokenException('Cannot decode header', InvalidTokenException::TOKEN_PARSE_ERROR);

            $result['signatures'][] = [
                'headers' => array_merge($headers, $signature['unprotected']),
                'signing_input' => $signature['protected'] . '.' . $payload,
                'signature' => $signature['signature']
            ];
        };
        
        return $result;
    }

    /**
     * Alias for {@link JWT::deserialise()}.
     * 
     * @codeCoverageIgnore
     */
    public static function deserialize($token) {
        return self::deserialise($token);
    }

    /**
     * Calculates an OpenID Connect token hash of a serialised JWT.  The JWT must be
     * in a compact JWT serialisation format.
     *
     * The token hash is the left-most half of the hash, with the hash algorithm
     * being the one specified by the `alg` header parameter.  For instance, if the signature
     * algorithm is RS256, the underlying hash algorithm is SHA-256, and this function
     * will return the encoded value of the left-most 128 bits of the SHA-256 hash.
     *
     * @param string $token the serialised JWT
     * @return string the base64url encoded short hash
     * @throws \InvalidArgumentException if the supplied token is not in a compact format
     * @throws \SimpleJWT\Crypt\CryptException if there is an error in the cryptographic process
     */
    public static function tokenHash($token) {
        $detect_result = Helper::detect($token);
        if ($detect_result['format'] != self::COMPACT_FORMAT)
            throw new \InvalidArgumentException('Only compact format JWTs are permitted');
        
        $deserialised = self::deserialise($token);
        $alg = $deserialised['signatures'][0]['headers']['alg'];

        /** @var \SimpleJWT\Crypt\SignatureAlgorithm $signer */
        $signer = AlgorithmFactory::create($alg);
        return $signer->shortHash($token);
    }
}
?>
