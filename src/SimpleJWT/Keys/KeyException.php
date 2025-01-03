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

namespace SimpleJWT\Keys;

/**
 * An exception associated with processing JSON web keys.
 */
class KeyException extends \RuntimeException {
    /**
     * Error code indicating that the source data is invalid.
     */
    const INVALID_KEY_ERROR = 1;

    /**
     * Error code indicating that a feature, while possibly compliant
     * with the encoding specification, is not currently supported by the
     * encoder.
     */
    const NOT_SUPPORTED_ERROR = 2;

    /**
     * Error code indicating that a key matching the required criteria
     * cannot be found in the supplied keyset
     */
    const KEY_NOT_FOUND_ERROR = 3;

    /**
     * Error code indicating that an error occurred in an underlying
     * system library (such as openssl or libsodium).
     */
    const SYSTEM_LIBRARY_ERROR = 4;

    /**
     * Error code indicating that the key is encrypted and cannot be
     * decrypted.
     */
    const KEY_DECRYPTION_ERROR = 5;

    /**
     * Error code indicating that the specified key already exists
     * in the key set.
     */
    const KEY_ALREADY_EXISTS_ERROR = 6;
}

?>
