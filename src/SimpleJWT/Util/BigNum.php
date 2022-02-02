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

namespace SimpleJWT\Util;
 
/**
 * A generic big integer using the GMP library.
 */
class BigNum {
    /** @var resource the internal representation of the value */
    protected $value;

    /**
     * Creates a bignum.
     *
     * @param mixed $str An integer, a string in base 2 to 36, or a byte stream in base 256
     * @param int $base an integer between 2 and 36, or 256
     * @return resource a bignum
     */
    public function __construct($str, $base = 10) {
        switch ($base) {
            case 10:
                $this->value = gmp_init($str, 10);
                return;
                break;
            case 256:
                $bytes = array_merge(unpack('C*', $str));

                $value = (new BigNum(0))->value;
          
                foreach ($bytes as $byte) {
                    $value = $this->_mul($value, 256);
                    $value = $this->_add($value, (new BigNum($byte))->value);
                }
                $this->value = $value;
                return;
                break;
            default:
                if (!is_integer($base) || ($base < 2) || ($base > 36)) return FALSE;

                $value = (new BigNum(0))->value;

                for ($i = 0; $i < strlen($str); $i++) {
                    $value = $this->_mul($value, $base);
                    $value = $this->_add($value, (new BigNum(base_convert($str[$i], $base, 10)))->value);
                }
                $this->value = $value;
                return;
        }

        throw new \RuntimeException();
    }

    /**
     * Adds two bignums
     *
     * @param BigNum $b
     * @return BigNum a bignum representing this + b
     */
    function add($b) {
        $result = new BigNum(0);
        $result->value = $this->_add($this->value, $b->value);
        return $result;
    }

    /**
     * Multiplies two bignums
     *
     * @param BigNum $b
     * @return BigNum a bignum representing this * b
     */
    function mul($b) {
        $result = new BigNum(0);
        $result->value = $this->_mul($this->value, $b->value);
        return $result;
    }

    /**
     * Raise base to power exp
     *
     * @param BigNum $exp the exponent
     * @return BigNum a bignum representing this ^ exp
     */
    function pow($exp) {
        $result = new BigNum(0);
        $result->value = $this->_pow($this->value, $exp->value);
        return $result;
    }

    /**
     * Divides two bignums
     *
     * @param BigNum $b
     * @return BigNum a bignum representing this / b
     */
    function div($b) {
        $result = new BigNum(0);
        $result->value = $this->_div($this->value, $b->value);
        return $result;
    }

    /**
     * Returns n modulo d
     *
     * @param BigNum $d
     * @return BigNum a bignum representing this mod d
     */
    function mod($d) {
        $result = new BigNum(0);
        $result->value = $this->_mod($this->value, $d->value);
        return $result;
    }

    /**
     * Raise a number into power with modulo
     *
     * @param BigNum $exp the exponent
     * @param BigNum $mod the modulo
     * @return BigNum a bignum representing this ^ exp mod mod
     */
    function powmod($exp, $mod) {
        $result = new BigNum(0);
        $result->value = $this->_powmod($this->value, $exp->value, $mod->value);
        return $result;
    }

    /**
     * Compares two bignum
     *
     * @param BigNum $b
     * @return int positive value if this > b, zero if this = b and a negative value if this < b
     */
    function cmp($b) {
        return $this->_cmp($this->value, $b->value);
    }

    /**
     * Returns a string representation.
     *
     * @return string
     */
    function __toString() {
        return gmp_strval($this->value, 10);
    }

    /**
     * Adds two bignums
     *
     * @param resource $a
     * @param resource $b
     * @return resource a bignum representing a + b
     */
    protected function _add($a, $b) {
        return gmp_add($a, $b);
    }

    /**
     * Multiplies two bignums
     *
     * @param resource $a
     * @param resource $b
     * @return resource a bignum representing a * b
     */
    protected function _mul($a, $b) {
        return gmp_mul($a, $b);
    }

    /**
     * Divides two bignums
     *
     * @param resource $a
     * @param resource $b
     * @return resource a bignum representing a / b
     */
    protected function _div($a, $b) {
        return gmp_div($a, $b);
    }

    /**
     * Raise base to power exp
     *
     * @param resource $base the base
     * @param mixed $exp the exponent, as an integer or a bignum
     * @return resource a bignum representing base ^ exp
     */
    function _pow($base, $exp) {
        if ((is_resource($exp) && (get_resource_type($exp) == 'GMP integer'))
            || (is_object($exp) && (get_class($exp) == 'GMP')))
            $exp = gmp_intval($exp);
        return gmp_pow($base, $exp);
    }

    /**
     * Returns n modulo d
     *
     * @param resource $n
     * @param resource $d
     * @return resource a bignum representing n mod d
     */
    protected function _mod($n, $d) {
        return gmp_mod($n, $d);
    }

    /**
     * Raise a number into power with modulo
     *
     * @param resource $base the base
     * @param resource $exp the exponent
     * @param resource $mod the modulo
     * @return resource a bignum representing base ^ exp mod mod
     */
    protected function _powmod($base, $exp, $mod) {
        return gmp_powm($base, $exp, $mod);
    }

    /**
     * Compares two bignum
     *
     * @param resource $a
     * @param resource $b
     * @return int positive value if a > b, zero if a = b and a negative value if a < b
     */
    protected function _cmp($a, $b) {
        return gmp_cmp($a, $b);
    }
}

?>
