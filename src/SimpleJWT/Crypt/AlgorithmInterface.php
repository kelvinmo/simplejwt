<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2023-2024
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

use SimpleJWT\Keys\Key;
use SimpleJWT\Keys\KeySet;

/**
 * Interface for a cryptographic algorithm.
 *
 * Algorithms will ordinarily implement one or more of the subinterfaces
 * of this interface: {@link Signature\SignatureAlgorithm SignatureAlgorithm},
 * {@link Encryption\EncryptionAlgorithm EncryptionAlgorithm} or
 * {@link KeyManagement\KeyManagementAlgorithm KeyManagementAlgorithm}.
 */
interface AlgorithmInterface {

    const SIGNATURE_ALGORITHM = 'sig';
    const ENCRYPTION_ALGORITHM = 'enc';
    const KEY_ALGORITHM = 'key';

    /**
     * Returns the name of the algorithm.
     *
     * @return string|null the algorithm
     */
    public function getAlg(): ?string;

    /**
     * Get `alg` or `enc` values supported by this class.
     *
     * Implementations should test the host system's configuration to determine
     * an algorithm is supported.  For example, if an algorithm requires a
     * particular PHP extension to be installed, then this method should test
     * the presence of this extension before including the algorithm in the
     * return value.
     *
     * @return array<string> an array of supported algorithms
     */
    public function getSupportedAlgs(): array;
}

?>
