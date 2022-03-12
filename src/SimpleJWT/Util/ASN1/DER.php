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

namespace SimpleJWT\Util\ASN1;

/**
 * Functions for interacting with ASN.1 data streams.
 *
 * Note that this class only implements a small subset of the ASN.1 DER, and should
 * not be used as a general-purpose ASN.1 encoder/decoder.
 */
class DER {
    /**
     * Reads a DER stream and decodes a single object
     *
     * @param string $data the data stream
     * @return Value the decoded value
     * @throws ASN1Exception if an error occurred
     */
    function decode(string $data): Value {
        $pos = 0;
        $value = $this->decodeNext($data, $pos);
        if ($value == null) {
            throw new ASN1Exception('Data too short');
        }
        return $value;
    }

    /**
     * Reads a DER stream and decodes the next object at a specified position.
     *
     * @param string $data the data stream
     * @param int &$pos the position of the data stream containing the object
     * to decode
     * @return Value|null the decoded value, or null if the end of the
     * stream has been reached
     */
    protected function decodeNext(string $data, int &$pos): ?Value {
        $value = '';
        $additional = [];

        $size = strlen($data);
        if ($size < 2) throw new ASN1Exception('Data too short');
        if ($pos >= $size) return null;  // End of stream

        // Identifier
        $id = $data[$pos++];
        $is_constructed = boolval((ord($id) >> 5) & 0x01);
        $class = ord($id) & 0xc0;
        $tag = ord($id) & 0x1f;
        if ($tag == 0x1f) throw new ASN1Exception('Long-form type not supported');

        // Length
        $len = ord($data[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | ord($data[$pos++]);
            }
        }
        if (($len > 0) && ($pos >= $size || $len > $size - $pos)) throw new ASN1Exception('Data too short');

        // Contents
        $contents = substr($data, $pos, $len);
        if (strlen($contents) != $len) throw new ASN1Exception('Invalid content length: expected ' . $len . ', got' . strlen($contents));

        if ($class == Value::UNIVERSAL_CLASS) {
            switch ($tag) {
                case Value::INTEGER_TYPE:
                    if ($is_constructed) throw new ASN1Exception('Integer type encoded as constructed');
                    $value = $this->decodeInteger($contents);
                    break;
                case Value::BIT_STRING:
                    $additional = $this->decodeBitString($contents);
                    $value = $additional['value'];
                    unset($additional['value']);
                    break;
                case Value::OCTET_STRING:
                    $value = $contents;
                    break;
                case Value::NULL_TYPE:
                    if ($is_constructed) throw new ASN1Exception('Null type encoded as constructed');
                    if ($len > 0) throw new ASN1Exception('Null type has length specified');
                    break;
                case Value::OID:
                    $value = $this->decodeOID($contents);
                    break;
                case Value::SEQUENCE:
                    if (!$is_constructed) throw new ASN1Exception('Sequence type not encoded as constructed');
                    $child_pos = 0;
                    $value = [];
                    while (($child = $this->decodeNext($contents, $child_pos)) != null) {
                        $value[] = $child;
                    }
                    break;
                default:
                    throw new ASN1Exception('Universal type not supported: ' . $tag);
            }
        } elseif ($is_constructed) {
            $child_pos = 0;
            if (($child = $this->decodeNext($contents, $child_pos)) != null) {
                $value = $child;
            } else {
                throw new ASN1Exception('Incorrect constructed encoding');
            }
        } else {
            throw new ASN1Exception('Type not supported: 0x' . bin2hex($id));
        }

        $pos += $len;

        return new Value($tag, $value, $additional, $is_constructed, $class);
    }


    /**
     * Encodes a value into its DER form.
     * 
     * @param Value $value the value to encode
     * @return string the encoded binary string
     * @throws ASN1Exception if an error occurs
     */
    function encode(Value $value): string {
        $tag = $value->getTag();

        // Contents
        if ($value->isConstructed()) {
            /** @var Value|array<Value> $children */
            $children = $value->getValue();

            if (is_array($children)) {
                $contents = '';
                foreach ($children as $child) {
                    $contents .= $this->encode($child);
                }
            } else {
                $contents = $this->encode($children);
            }
        } else {
            $val = $value->getValue();
            $additional = $value->getAdditionalData();

            switch ($tag) {
                case Value::INTEGER_TYPE:
                    $contents = $this->encodeInteger($val);
                    break;
                case Value::BIT_STRING:
                    if (!isset($additional['bitstring_length']))
                        throw new ASN1Exception('Length not specified in bit string');
                    $contents = $this->encodeBitString($val, $additional['bitstring_length']);
                    break;
                case Value::OCTET_STRING:
                    $contents = $val;
                    break;
                case Value::NULL_TYPE:
                    $contents = '';
                    break;
                case Value::OID:
                    $contents = $this->encodeOID($val);
                    break;
                default:
                    throw new ASN1Exception('Type not supported: ' . $tag);
            }
        }

        // Length
        $len = strlen($contents);
        if ($len <= 0x7f) {
            $encoded_length = chr($len);
        } else {
            $pack = '';
            $n = 0;
            while ($len) {
                $pack .= chr($len & 0xff);
                $len >>= 8;
                $n++;
            }

            if ($n >= 127) {
                throw new ASN1Exception('Encoded length too long');
            }

            $encoded_length = chr($n | 0x80);

            if (pack('V', 65534) == pack('L', 65534)) {
                $encoded_length .= strrev($pack); // Little endian machine - need to convert to big endian
            } else {
                $encoded_length .= $pack;
            }
        }

        // Identifier
        $type_header = $value->getClass();
        if ($value->isConstructed()) $type_header |= 0x20;

        if ($tag < 0x1f) {
            $id = chr($type_header | $tag);
        } else {
            throw new ASN1Exception('Long form tags not supported.');
        }

        return $id . $encoded_length . $contents;
    }


    /**
     * @param string $data
     * @return int|\GMP
     */
    static function decodeInteger($data) {
        static $int_min;
        static $int_max;

        if (!isset($int_min)) $int_min = gmp_init(PHP_INT_MIN);
        if (!isset($int_max)) $int_max = gmp_init(PHP_INT_MAX);

        if (strlen($data) == 0) return 0;

        $is_negative = (ord($data[0]) & 0x80);
        if ($is_negative) $data = ~$data;

        $gmp = gmp_import($data);
        if ($is_negative) $gmp = gmp_neg(gmp_add($gmp, 1));

        if ((gmp_cmp($gmp, $int_min) >= 0) &&
            (gmp_cmp($gmp, $int_max) <= 0)) {
            return gmp_intval($gmp);
        } else {
            return $gmp;
        }
    }

    /**
     * @param int|\GMP $int
     * @return string
     */
    static function encodeInteger($int) {
        $is_bigint = ($int instanceof \GMP);
        $is_negative = ($is_bigint) ? (gmp_sign($int) < 0): ($int < 0);

        if ($is_negative) throw new ASN1Exception('Negative numbers not supported');

        if (!$is_bigint) $int = gmp_init($int);
        $data = gmp_export($int);

        if (strlen($data) == 0) return "\0";
        if (ord($data) > 127) return "\0" . $data;
        return $data;
    }

    /**
     * @param string $data
     * @return array<string, mixed>
     */
    static function decodeBitString($data) {
        $unused_bits = ord($data[0]);
        if ($unused_bits > 7) throw new ASN1Exception('Incorrect unused bit length in bit string: ' . $unused_bits);

        $bits = substr($data, 1);

        return [
            'value' => $bits,
            'bitstring_length' => strlen($bits) * 8 - $unused_bits
        ];
    }

    /**
     * @param string $data
     * @param int $length
     * @return string
     */
    static function encodeBitString($data, $length) {
        if (($length % 8) == 0) {
            $unused_bits = 0;
        } else {
            $unused_bits = 8 - ($length % 8);
        }
        
        return chr($unused_bits) . $data;
    }


    /**
     * Decodes a DER-encoded object identifier into a string.
     *
     * @param string $oid the binary DER-encoded object identifier
     * @return string the decoded string
     */
    static function decodeOID($oid) {
        $pos = 0;
        $size = strlen($oid);

        // First octet
        $oct = ord($oid[$pos++]);
        $str = floor($oct / 40) . '.' . ($oct % 40);

        // Subsequent octets
        while ($pos < $size) {
            $num = 0;

            do {
                $oct = ord($oid[$pos++]);
                $num = ($num << 7) + ($oct & 0x7F);
            } while (($oct & 0x80) && ($pos < $size));

            $str .= '.' . $num;
        }

        return $str;
    }

    /**
     * Encodes a string into a DER-encoded object identifier.
     *
     * @param string $str the object identifier string
     * @return string the binary DER-encoded object identifier
     */
    static function encodeOID($str) {
        $numbers = explode('.', $str);

        // First octet
        $oid = chr(intval(array_shift($numbers)) * 40 + intval(array_shift($numbers)));

        // Subsequent octets
        foreach ($numbers as $num) {
            if ($num == 0) {
                $oid .= chr(0x00);
                continue;
            }
            $pack = '';

            while ($num) {
                $pack .= chr(0x80 | ($num & 0x7f));
                $num >>= 7;
            }
            $pack[0] = $pack[0] & chr(0x7f);

            if (pack('V', 65534) == pack('L', 65534)) {
                $oid .= strrev($pack); // Little endian machine - need to convert to big endian
            } else {
                $oid .= $pack;
            }
        }

        return $oid;
    }
}

?>
