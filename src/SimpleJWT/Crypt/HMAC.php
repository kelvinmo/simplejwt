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

namespace SimpleJWT\Crypt;

use SimpleJWT\Keys\KeyException;
use SimpleJWT\Util\Util;

/**
 * HMAC-based signature algorithm.
 *
 * This class implements the `HS256`, `HS384` and `HS512` algorithms.
 *
 */
class HMAC extends SHA2 {
    public function __construct($alg) {
        if ($alg == null) {
            parent::__construct(null, null);
        } else {
            parent::__construct($alg, filter_var($alg, FILTER_SANITIZE_NUMBER_INT));
        }
    }

    public function getKeyCriteria() {
        return ['kty' => 'oct', '@use' => 'sig', '@key_ops' => ['sign', 'verify']];
    }

    public function getSupportedAlgs() {
        $results = [];
        $hash_algos = hash_algos();
        if (in_array('sha256', $hash_algos)) $results[] = 'HS256';
        if (in_array('sha384', $hash_algos)) $results[] = 'HS384';
        if (in_array('sha512', $hash_algos)) $results[] = 'HS512';

        return $results;
    }

    public function sign($data, $keys, $kid = null) {
        $key = $this->getSigningKey($keys, $kid);
        if (($key == null) || !is_a($key, 'SimpleJWT\Keys\SymmetricKey')) {
            throw new KeyException('Key not found or is invalid');
        }
        return Util::base64url_encode(hash_hmac('sha' . $this->size, $data, $key->toBinary(), true));
    }

    public function verify($signature, $data, $keys, $kid = null) {
        $compare = $this->sign($data, $keys, $kid);
        return Util::secure_compare($signature, $compare);
    }

    public function getSigningKey($keys, $kid = null) {
        return $this->selectKey($keys, $kid);
    }
}

?>
