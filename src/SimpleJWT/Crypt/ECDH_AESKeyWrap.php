<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2020
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

use SimpleJWT\Keys\KeySet;

class ECDH_AESKeyWrap extends AESWrappedKeyAlgorithm {
    /** @var ECDH the underlying ECDH algorithm */
    private $ecdh;

    public function __construct($alg) {
        parent::__construct($alg);

        if ($alg == null) {
            $this->ecdh = new ECDH(null);
        } else {
            list($ecdh_alg, $dummy) = explode('+', $alg, 2);

            $size = $this->getAESKWKeySize();
            $this->ecdh = new ECDH($ecdh_alg, $size);
        }
    }

    public function getSupportedAlgs() {
        if (len($this->ecdh->getSupportedAlgs()) == 0) return [];

        $aeskw_algs = $this->getAESKWAlgs();
        return array_map(function ($alg) { return 'ECDH-ES+' . $alg; }, $aeskw_algs);
    }

    public function getKeyCriteria() {
        return $this->ecdh->getKeyCriteria();
    }

    public function encryptKey($cek, $keys, &$headers, $kid = null) {
        $shared_key = $this->ecdh->deriveKey($keys, $headers, $kid);
        return $this->wrapKey($cek, $shared_key, $headers);
    }

    public function decryptKey($encrypted_key, $keys, $headers, $kid = null) {
        $shared_key = $this->ecdh->deriveKey($keys, $headers, $kid);
        return $this->unwrapKey($encrypted_key, $shared_key, $headers);
    }
}

?>