<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2022
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
 * A JSON Object Signing and Encryption (JOSE) token.
 * 
 * A JOSE token can be a JSON web token (JWT) or a JSON web encryption
 * (JWE).  These are represented by the subclasses {@link JWE} and
 * {@link JWT} respectively.
 */
abstract class Token {
    /** @var string COMPACT_FORMAT Compact token serialisation format */
    const COMPACT_FORMAT = 'compact';
    /** @var string JSON_FORMAT JSON token serialisation format */
    const JSON_FORMAT = 'json';

    /** @var array<string, mixed> $headers */
    protected $headers;

    /**
     * Creates a new token.
     *
     * @param array<string, mixed> $headers the headers
     */
    public function __construct($headers) {
        $this->headers = $headers;
    }

    /**
     * Returns the token's headers.
     *
     * @return array<string, mixed> the headers
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
}
?>
