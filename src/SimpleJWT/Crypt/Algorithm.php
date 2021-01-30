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

/**
 * The base class representing a family of JSON web algorithms.  A family of
 * algorithms is a set of algorithms related in some way: e.g. same underlying
 * algorithm but with different key or output sizes, or algorithms supported
 * by a particular cryptographic library.
 *
 * The actual `alg` or `enc` to be used is specified by the `$alg` parameter
 * in the constructor.
 *
 * Algorithms will ordinarily implement one or more of {@link SignatureAlgorithm},
 * {@link EncryptionAlgorithm} or {@link KeyManagementAlgorithm} interfaces.
 */
abstract class Algorithm {

    const SIGNATURE_ALGORITHM = 'sig';
    const ENCRYPTION_ALGORITHM = 'enc';
    const KEY_ALGORITHM = 'key';

    private $alg;

    /**
     * Creates an algorithm.
     *
     * The algorithm is specified in the `$alg` parameter.  If `$alg` is `null`,
     * the object will represent the entire family of algorithms - in which case
     * only the {@link getSupportedAlgs()} function will work.
     *
     * @param string $alg the algorithm
     * @throws \UnexpectedValueException if the `$alg` parameter is not supported
     * by this class
     */
    protected function __construct($alg = null) {
        if (($alg != null) && !in_array($alg, $this->getSupportedAlgs())) throw new \UnexpectedValueException('Algorithm not supported: ' . $alg);
        $this->alg = $alg;
    }

    /**
     * Returns the name of the algorithm.
     *
     * @return string|null the algorithm
     */
    public function getAlg() {
        return $this->alg;
    }

    /**
     * Get `alg` or `enc` values supported by this class.
     *
     * Implementations should test the host system's configuration
     *
     * @return array supported algorithms
     */
    abstract public function getSupportedAlgs();

    /**
     * Select the key from the key set that can be used by this algorithm.
     *
     * The criteria specified in this function is combined with the default
     * criteria for the algorithm (through the {@link getKeyCriteria()} function)
     * before it is bassed to the {@link SimpleJWT\Keys\KeySet::get()} function
     * to retrieve the key.
     *
     * `$criteria` can be one of the following:
     *
     * 1. `null`, in which case only the default criteria are used
     * 2. a string containing the key ID; or
     * 3. an array compatible with the {@link SimpleJWT\Keys\KeySet::get()} function
     *
     * @param SimpleJWT\Keys\KeySet $keys the key set from which the key will
     * be selected
     * @param array|string $criteria the criteria
     */
    protected function selectKey() {
        $args = func_get_args();
        $keys = array_shift($args);
        
        $criteria = $this->getKeyCriteria();
        
        foreach ($args as $arg) {
            if ($arg == null) continue;
            if (is_string($arg)) {
                $criteria = array_merge($criteria, ['kid' => $arg]);
            } elseif (is_array($arg)) {
                $criteria = array_merge($criteria, $arg);
            }
        }

        return $keys->get($criteria);
    }

    /**
     * Returns the criteria for selecting keys
     *
     * @param array the key selection criteria
     */
    abstract public function getKeyCriteria();
}

?>
