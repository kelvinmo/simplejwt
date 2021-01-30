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

namespace SimpleJWT;

/**
 * An exception where a JWT or JWE is invalid or cannot be decoded for any reason.
 */
class InvalidTokenException extends \RuntimeException {
    /** An error code indicating that the JWT or JWE cannot be parsed
     * (e.g. not a valid JSON object) */
    const TOKEN_PARSE_ERROR = 0;

    /** An error code indicating that the JWT or JWE contains critical claims
     * that are not supported by SimpleJWT */
    const UNSUPPORTED_ERROR = 1;

    /** An error code indicating that the JWT's signature cannot be verified.
     * This may be due to the lack of a key, cryptographic errors, or the
     * signature is incorrect. */
    const SIGNATURE_VERIFICATION_ERROR = 16;

    /** An error code indicating that the JWE cannot be decrypted.
     * This may be due to the lack of a key, cryptographic errors, or the
     * authentication information is incorrect. */
    const DECRYPTION_ERROR = 17;

    /** An error code indicating that the JWT or JWE is invalid as a result
     * of the `nbf` claim.  The time that the token is valid can be obtained
     * using the {@link getTime()} function. */
    const TOO_EARLY_ERROR = 256;

    /** An error code indicating that the JWT or JWE is invalid as a result
     * of the `exp` claim.  The time that the token was valid until can be obtained
     * using the {@link getTime()} function. */
    const TOO_LATE_ERROR = 257;

    protected $time;

    /**
     * Creates an InvalidTokenException
     * 
     * @param string $message the exception message
     * @param int $code the exception code
     * @param Exception $previous the underlying exception
     * @param int $time for TOO_EARLY_ERROR or TOO_LATE_ERROR, the required time specified
     * in the token
     */
    public function __construct($message = "", $code = 0, $previous = NULL, $time = 0) {
        parent::__construct($message, $code, $previous);
        $this->time = $time;
    }

    /**
     * Returns the required time specified in the token.
     * 
     * @return int the required time time
     */
    public function getTime() {
        return $this->time;
    }
}

?>
