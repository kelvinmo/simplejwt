<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2015-2024
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

use \UnexpectedValueException;

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
    static public function base64url_encode(string $data, bool $pad = false): string {
        $encoded = strtr(base64_encode($data), '+/', '-_');
        if (!$pad) $encoded = trim($encoded, '=');
        return $encoded;
    }

    /**
     * Decodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the encoded data
     * @return string the original data. The returned data may be binary.
     * @link http://tools.ietf.org/html/rfc4648#section-5
     * @throws UnexpectedValueException if an error occurs in the decoding process
     */
    static public function base64url_decode(string $data): string {
        $decoded = base64_decode(strtr($data, '-_', '+/'));
        if ($decoded == false) {
            throw new UnexpectedValueException('Invalid base64url string');
        }
        return $decoded;
    }

    /**
     * Replaces the keys of an array with specified replacements.
     * 
     * @param array<mixed, mixed> $array
     * @param array<mixed, mixed> $replacements
     * @return array<mixed, mixed>
     */
    static public function array_replace_keys(array $array, array $replacements): array {
        return array_combine(self::array_replace_values(array_keys($array), $replacements), $array);
    }

    /**
     * Replaces the values of an array with specified replacements.
     * 
     * @param array<mixed> $array
     * @param array<mixed, mixed> $replacements
     * @return array<mixed>
     */
    static public function array_replace_values(array $array, array $replacements): array {
        return array_map(function ($value) use ($replacements) {
            return isset($replacements[$value]) ? $replacements[$value] : $value;
        }, $array);
    }

    /**
     * Compares two strings using the same time whether they're equal or not.
     * This function should be used to mitigate timing attacks when, for
     * example, comparing password hashes
     * 
     * This function calls `hash_equals()` to perform the comparion.  It
     * is retained for compatibility with earlier versions
     * of SimpleJWT.
     *
     * @param string $str1
     * @param string $str2
     * @return bool true if the two strings are equal
     */
    static public function secure_compare(string $str1, string $str2): bool {
        return hash_equals($str1, $str2);
    }

    /**
     * Converts an interger into a 64-bit big-endian byte string.
     *
     * @param int $x the interger
     * @return string the byte string
     */
    static function packInt64(int $x): string {
        if (PHP_INT_SIZE == 8) {
            return pack('J', $x);
        } else {
            // 32-bit system
            return "\x00\x00\x00\x00" . pack('N', $x);
        }
    }

    /**
     * Obtains a number of random bytes.
     * 
     * This function is retained for compatibility with earlier versions
     * of SimpleJWT.
     *
     * @param int<1, max> $num_bytes the number of bytes to generate
     * @return string a string containing random bytes
     */
    static function random_bytes(int $num_bytes): string {
        return random_bytes($num_bytes);
    }

    /**
     * Returns whether an array is a list.
     * 
     * This is a polyfill for PHP 8.1's array_as_list function.
     * 
     * @param array<mixed> $array
     * @return bool if the array is a list
     */
    public static function array_is_list(array $array): bool {
        if (function_exists('array_is_list')) return \array_is_list($array);
        return $array === [] || (array_keys($array) === range(0, count($array) - 1));
    }
}

?>
