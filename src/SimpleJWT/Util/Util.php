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

namespace SimpleJWT\Util;

/**
 * Miscellaneous utility functions.
 */
class Util {
    /**
     * Encodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the data to encode
     * @param bool $pad whether padding characters should be included
     * @return string the encoded data
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    static public function base64url_encode($data, $pad = false) {
        $encoded = strtr(base64_encode($data), '+/', '-_');
        if (!$pad) $encoded = trim($encoded, '=');
        return $encoded;
    }

    /**
     * Decodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the encoded data
     * @return string|bool the original data or FALSE on failure. The returned data may be binary.
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    static public function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Compares two strings using the same time whether they're equal or not.
     * This function should be used to mitigate timing attacks when, for
     * example, comparing password hashes
     *
     * @param string $str1
     * @param string $str2
     * @return bool true if the two strings are equal
     */
    static public function secure_compare($str1, $str2) {
        if (function_exists('hash_equals')) return hash_equals($str1, $str2);

        $xor = $str1 ^ $str2;
        $result = strlen($str1) ^ strlen($str2); //not the same length, then fail ($result != 0)
        for ($i = strlen($xor) - 1; $i >= 0; $i--) $result += ord($xor[$i]);
        return !$result;
    }

    /**
     * Converts an interger into a 64-bit big-endian byte string.
     *
     * @param int $x the interger
     * @return string the byte string
     */
    static function packInt64($x) {
        if (PHP_INT_SIZE == 8) {
            if (version_compare(PHP_VERSION, '5.6.3', '>=')) {
                return pack('J', $x);
            } else {
                return pack('NN', ($x & 0xFFFFFFFF00000000) >> 32, $x & ($x & 0x00000000FFFFFFFF)); 
            }
        } else {
            // 32-bit system
            return "\x00\x00\x00\x00" . pack('N', $x);
        }
    }

    /**
     * Obtains a number of random bytes.  For PHP 7 and later, this function
     * calls the native `random_bytes()` function.  For older PHP versions, this
     * function uses an entropy source specified in $rand_source or the OpenSSL
     * or mcrypt extensions.  If $rand_source is not available, the mt_rand()
     * PHP function is used.
     *
     * @param int $num_bytes the number of bytes to generate
     * @param string $rand_source file path to entropy source
     * @return string a string containing random bytes
     */
    static function random_bytes($num_bytes, $rand_source = '/dev/urandom') {
        // 1. Try random_bytes first
        if (function_exists('random_bytes')) return random_bytes($num_bytes);

        // 2. Try mcrypt or openssl
        $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

        if ($is_windows) {
            // Windows
            if (function_exists('mcrypt_create_iv') && version_compare(PHP_VERSION, '5.3.7', '>='))
                return mcrypt_create_iv($num_bytes);

            if (function_exists('openssl_random_pseudo_bytes') && version_compare(PHP_VERSION, '5.3.4', '>='))
                return openssl_random_pseudo_bytes($num_bytes);
        }

        if (!$is_windows && function_exists('openssl_random_pseudo_bytes'))
            return openssl_random_pseudo_bytes($num_bytes);

        // 3. Try $rand_source or mt_rand
        $bytes = '';
        
        // $rand_source is insecure on Windows (e.g. C:\dev\urandom would be read)
        if (($rand_source === null) || $is_windows || !is_readable($rand_source)) {
            $f = FALSE;
        } else {
            $f = @fopen($rand_source, "r");
        }
        
        if ($f === FALSE) {
            $bytes = '';
            for ($i = 0; $i < $num_bytes; $i += 4) {
                $bytes .= pack('L', mt_rand());
            }
            $bytes = substr($bytes, 0, $num_bytes);
        } else {
            $bytes = fread($f, $num_bytes);
            fclose($f);
        }
        return $bytes;
    }
}

?>
