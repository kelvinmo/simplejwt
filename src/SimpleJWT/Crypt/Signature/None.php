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

namespace SimpleJWT\Crypt\Signature;

use SimpleJWT\Crypt\BaseAlgorithm;
use SimpleJWT\Keys\KeyInterface;
use SimpleJWT\Keys\KeySet;

/**
 * Implements the `none` signature algorithm.
 * 
 * Note that the `none` algorithm should only be used in JWTs which
 * are cryptographically protected by other means.
 * 
 * By default, the `none` algorithm is disabled in SimpleJWT.  Attempts
 * to decode a JWT with a `none` algorithm will return a
 * {@link \SimpleJWT\InvalidTokenException InvalidTokenException}.
 * In order to enable this algorithm, call the 
 * {@link \SimpleJWT\Crypt\AlgorithmFactory::addNoneAlg()} static
 * method.
 * 
 * @link https://datatracker.ietf.org/doc/html/rfc8725.html#section-3.2
 * @codeCoverageIgnore
 */
class None extends BaseAlgorithm implements SignatureAlgorithm {
    public function __construct(?string $alg) {
        parent::__construct($alg);
    }

    public function getKeyCriteria(): array {
        return [];
    }

    public function getSupportedAlgs(): array {
        return ['none'];
    }

    public function sign(string $data, KeySet $keys, ?string $kid = null): string {
        return '';
    }

    public function shortHash(string $data): string {
        return '';
    }

    public function verify(string $signature, string $data, KeySet $keys, ?string $kid = null): bool {
        if ($kid != null) return false;
        return ($signature === '');
    }

    public function getSigningKey(KeySet $keys, ?string $kid = null): ?KeyInterface {
        return null;
    }
}

?>
