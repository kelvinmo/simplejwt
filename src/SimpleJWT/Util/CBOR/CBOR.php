<?php
/*
 * SimpleJWT
 *
 * Copyright (C) Kelvin Mo 2023
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

namespace SimpleJWT\Util\CBOR;

/**
 * Functions for interacting with CBOR data structures.
 *
 * Note that this class only implements a small subset of the CBOR
 * specification, and should not be used as a general-purpose CBOR
 * encoder/decoder.
 */
class CBOR {
    /**
     * Decodes a single CBOR object
     *
     * @param string $data the CBOR object
     * @param int $mode the decoding mode
     * @return mixed|DataItem the decoded object
     * @throws CBORException if an error occurred
     */
    function decode(string $data, int $mode = DataItem::DECODE_NATIVE) {
        $pos = 0;
        $value = $this->decodeNext($data, $pos);
        if ($value == null) {
            throw new CBORException('Data too short');
        }
        return $value->getValue($mode);
    }

    /**
     * Reads a CBOR object and decodes the next child object at a specified position.
     * 
     * The position is specified in the `$pos` parameter.  This variable is
     * updated to the position of the next data item upon a successful read.
     *
     * @param string $data the data structure
     * @param int &$pos the position of the data structure containing the item
     * to decode
     * @return DataItem|null the decoded item, or null if the end of the
     * stream has been reached
     * @throws CBORException if an error occurred
     */
    protected function decodeNext(string $data, int &$pos): ?DataItem {
        $type = null;
        $value = '';
        $argument_length = null;
        $argument_bytes = '';

        $size = strlen($data);
        if ($size == 0) throw new CBORException('Data too short');
        if ($pos >= $size) return null;  // End of stream

        // 1. Read and parse initial byte
        $initial = ord($data[$pos++]);
        $major_type = $initial & 0b11100000; // Major type constants in DataItem are not shifted
        $additional = $initial & 0b00011111;

        // 2. Parse major type 7 (which has fixed argument lengths)
        if ($major_type == DataItem::OTHER_MAJOR_TYPE) {
            $type = $initial;
            switch ($initial) {
                case DataItem::FALSE_TYPE:
                    $argument_length = 0;
                    $value = false;
                    break;
                case DataItem::TRUE_TYPE:
                    $argument_length = 0;
                    $value = true;
                    break;
                case DataItem::NULL_TYPE:
                case DataItem::UNDEFINED_TYPE:
                case DataItem::BREAK_CODE:
                    $argument_length = 0;
                    $value = null;
                    break;
                case DataItem::FLOAT16_TYPE:
                    $argument_length = 2;
                    break;
                case DataItem::FLOAT32_TYPE:
                    $argument_length = 4;
                    break;
                case DataItem::FLOAT64_TYPE:
                    $argument_length = 8;
                    break;
                default:
                    $type = DataItem::SIMPLE_VALUE_TYPE;
                    if ($additional <= 19) {
                        $argument_bytes = chr($additional);
                        $argument_length = 0;
                    } else {
                        $argument_length = 1;
                    }
                    break;
            }
        } else {
            // 3. For major types apart from major type 7, determine
            //    argument length based on additional bits
            $type = $major_type;
            if ($additional < 24) {
                $argument_bytes = chr($additional);
                $argument_length = 0;
            } elseif ($additional <= 27) {
                $argument_length = 2 ** ($additional - 24);
            } elseif ($additional == 31) {
                throw new CBORException('Indefinite length items not supported');
            }
        }

        // 4. Read additional bytes for argument
        if ($argument_length > 0) {
            $argument_bytes = substr($data, $pos, $argument_length);
            if (strlen($argument_bytes) != $argument_length) throw new CBORException('Invalid argument size: expected ' . $argument_length . ' bytes, got ' . strlen($argument_bytes));
            $pos += $argument_length;
        }

        // 5. Parse argument, based on major type
        $content_length = 0;
        $item_count = 0;

        switch ($type) {
            case DataItem::UINT_TYPE:
            case DataItem::SIMPLE_VALUE_TYPE:
                $value = $this->decodeUInt($argument_bytes);
                break;
            case DataItem::NINT_TYPE:
                $uint = $this->decodeUInt($argument_bytes);
                if ($uint instanceof \GMP) {
                    $value = gmp_sub(-1, $uint);
                } else {
                    $value = -1 - $uint;
                }
                break;
            case DataItem::BSTR_TYPE:
            case DataItem::TSTR_TYPE:
                /** @var int $content_length */
                $content_length = $this->decodeUInt($argument_bytes, false);
                break;
            case DataItem::LIST_TYPE:
            case DataItem::MAP_TYPE:
                /** @var int $item_count */
                $item_count = $this->decodeUInt($argument_bytes, false);
                $value = [];
                break;
            case DataItem::TAG_TYPE:
                // If this is a tag type, the argument is the tag value, and the
                // contents is the next CBOR item
                /** @var int $tag */
                $tag = $this->decodeUInt($argument_bytes, false);
                $item = $this->decodeNext($data, $pos);
                $item->setTag($tag);
                return $item;
            case DataItem::FLOAT16_TYPE:
                $value = $this->decodeFloat16($argument_bytes);
                break;
            case DataItem::FLOAT32_TYPE:
                $value = $this->unpack('G', $argument_bytes);
                break;
            case DataItem::FLOAT64_TYPE:
                $value = $this->unpack('E', $argument_bytes);
                break;
            case DataItem::BREAK_CODE:
                return null;
            case DataItem::FALSE_TYPE:
            case DataItem::TRUE_TYPE:
            case DataItem::NULL_TYPE:
            case DataItem::UNDEFINED_TYPE:
                // Do nothing, as we've already done all that is required in 2.
                break;
            default:
                throw new CBORException('Major type not supported: ' . ($major_type >> 5));
        }

        // 6. Parse contents (for major types which have a content stream)
        if ($content_length > 0) {
            // bstr, tstr
            $contents = substr($data, $pos, $content_length);
            if (strlen($contents) != $content_length) throw new CBORException('Invalid content length: expected ' . $content_length . ', got ' . strlen($contents));
            $value = $contents;
            $pos += $content_length;
        } elseif ($item_count > 0) {
            // list, map
            switch ($type) {
                case DataItem::LIST_TYPE:
                    for ($i = 0; $i < $item_count; $i++) {
                        $child = $this->decodeNext($data, $pos);
                        $value[] = $child;
                        if ($child == null) throw new CBORException('Unexpected end of list');
                    }
                    break;
                case DataItem::MAP_TYPE:
                    for ($i = 0; $i < $item_count; $i++) {
                        $map_key = $this->decodeNext($data, $pos); // $pos is off by 2
                        $map_value = $this->decodeNext($data, $pos);
                        
                        if (($map_key == null) || ($map_value == null)) throw new CBORException('Unexpected end of map');
                        $key = $map_key->getValue();
                        if (!is_int($key) && !is_string($key)) throw new CBORException('Only integer and string map keys are supported');
                        if (isset($value[$key])) throw new CBORException('Duplicate key in map: ' . $key);
                        $value[$key] = $map_value;
                    }
                    break;
                default:
                    assert(true);
            }
        }

        return new DataItem($type, $value);
    }


    /**
     * Encodes a data item into CBOR.
     * 
     * @param DataItem $item the data item to encode
     * @return string the encoded binary string
     * @throws CBORException if an error occurs
     */
    function encode(DataItem $item): string {
        $result = '';

        $type = $item->getType();
        $tag = $item->getTag();

        // 1. Tag (if any)
        if ($tag != null) {
            $result = $this->encodeUInt(DataItem::TAG_TYPE, $tag);
        }

        // 2. Contents
        $value = $item->getValue();

        switch ($type) {
            case DataItem::UINT_TYPE:
            case DataItem::NINT_TYPE:
                if ($value < 0) {
                    $result .= $this->encodeUInt(DataItem::NINT_TYPE, $value);
                } else {
                    $result .= $this->encodeUInt(DataItem::UINT_TYPE, $value);
                }
                break;
            case DataItem::BSTR_TYPE:
            case DataItem::TSTR_TYPE:
                $content_length = strlen($value);
                $result .= $this->encodeUInt($type, $content_length) . $value;
                break;
            case DataItem::LIST_TYPE:
                $contents = '';
                foreach ($value as $child) {
                    $contents .= $this->encodeDefault($child);
                }
                $item_count = count($value);
                $result .= $this->encodeUInt($type, $item_count) . $contents;
                break;
            case DataItem::MAP_TYPE:
                $contents = '';
                $encoded_map = [];
                foreach ($value as $k => $v) {
                    $encoded_map[$this->encodeDefault($k)] = $this->encodeDefault($v);
                }
                ksort($encoded_map, SORT_STRING);
                foreach ($encoded_map as $k => $v) {
                    $contents .= $k . $v;
                }
                $item_count = count($value);
                $result .= $this->encodeUInt($type, $item_count) . $contents;
                break;
            case DataItem::TAG_TYPE:
                throw new CBORException('Tags cannot be encoded separately');
            case DataItem::FLOAT16_TYPE:
            case DataItem::FLOAT32_TYPE:
            case DataItem::FLOAT64_TYPE:
                $result .= $type . $this->encodeFloat($value);
                break;
            case DataItem::FALSE_TYPE:
            case DataItem::TRUE_TYPE:
            case DataItem::NULL_TYPE:
            case DataItem::UNDEFINED_TYPE:
            case DataItem::BREAK_CODE:
                $result .= $type;
                break;
            case DataItem::SIMPLE_VALUE_TYPE:
                if (($value >= 20) && ($value <= 31)) {
                    throw new CBORException('Cannot encode reserved simple value');
                }
                $result .= $this->encodeUInt($type, $value);
                break;
            default:
                throw new CBORException('Type not supported: ' . $type);
        }

        return $result;
    }

    /**
     * Decodes a float16 value.
     * 
     * @param string $data
     * @return float
     */
    protected function decodeFloat16($data) {
        $u16 = $this->unpack('n', str_pad($data, 2, "\x00", STR_PAD_LEFT));

        $exp = ($u16 >> 10) & 0x1f;
        $sig = $u16 & 0x3ff;

        if ($exp === 0) {
            $val = $sig * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($sig + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($sig === 0) ? INF : NAN;
        }

        return ($u16 & 0x8000) ? -$val : $val;
    }

    /**
     * Encodes a value as float16.
     * 
     * If the specified value cannot fit into a float16, positive infinity or negative
     * infinity is returned.
     * 
     * @param float $value the value to encode
     * @return string the encoded value
     */
    protected function encodeFloat16($value) {
        if ($value == 0) {
            return "\x00\x00";
        } elseif ($value == NAN) {
            return "\x7e\x00";  // quiet NaN
        } elseif ($value == INF) {
            return "\x7c\x00";
        } elseif (-$value == INF) {
            return "\xfc\x00";
        } else {
            // Convert to uint32 representation
            $u32 = $this->unpack('N', pack('G', $value));
            
            $exp32 = ($u32 >> 23) & 0xff;
            $exp16 = ($exp32 - 0x70) & (((0x70 - $exp32) >> 4) >> 27); // rebias exponent
            if ($exp16 > 31) {
                // too large to be encoded as a float16
                // encode as +Inf or -Inf, depending on the sign
                $exp16 = 0b11111;
                $u32 = $u32 & 0x80000000;
            }

            $result = ((($u32 >> 31) << 5) | $exp16) << 10;
            $result |= ($u32 >> 13) & 0x3ff;
            return pack('n', $result);
        }
    }

    /**
     * Encodes a float as short as possible.
     * 
     * This method tries to encode the value using float16, float32 and float64,
     * and selects the encoding that returns the same result once decoded.
     * 
     * @param float $value the value to encode
     * @return string
     */
    protected function encodeFloat($value) {
        $float64 = pack('E', $value);
        $float32 = pack('G', $value);
        $float16 = $this->encodeFloat16($value);

        if ($this->unpack('E', $float64) == $this->unpack('G', $float32)) {
            if ($this->unpack('G', $float32) == $this->decodeFloat16($float16)) {
                return $float16;
            } else {
                return $float32;
            }
        } else {
            return $float64;
        }
    }

    /**
     * Decodes an unsigned integer
     * 
     * @param string $data
     * @param bool $allow_gmp allows GMP objects to be returned.
     * @return int|\GMP
     */
    protected function decodeUInt($data, $allow_gmp = true) {
        if (strlen($data) <= 4) {
            return $this->unpack('N', str_pad($data, 4, "\x00", STR_PAD_LEFT));
        } elseif ((strlen($data) <= 8) && (PHP_INT_SIZE == 8)) {
            return $this->unpack('J', str_pad($data, 8, "\x00", STR_PAD_LEFT));
        } elseif ($allow_gmp) {
            return gmp_import($data, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        } else {
            throw new CBORException('Cannot decode integer');
        }
    }

    /**
     * Encodes an unsigned integer as short as possible.
     * 
     * For integers between 0 and 23 (inclusive), this means encoding the value
     * along with the major type.
     * 
     * @param int $type the encoded major type
     * @param int $value the value to encode
     * @return string
     * @see https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding
     */
    protected function encodeUInt($type, $value) {
        if ($value <= 23) {
            return chr($type | $value);
        } elseif ($value <= 255) {
            return chr($type | 24) . chr($value);
        } elseif ($value <= 65535) {
            return chr($type | 25) . pack('n', $value);
        } elseif ($value <= 4294967295) {
            return chr($type | 26) . pack('N', $value);
        } else {
            if (PHP_INT_SIZE < 8) throw new CBORException('64-bit values not supported by this system');
            return chr($type | 27) . pack('J', $value);
        }
    }

    /**
     * @param mixed $item
     * @return string
     */
    protected function encodeDefault($item) {
        if (!($item instanceof DataItem)) {
            $item = DataItem::default($item);
        }
        return $this->encode($item);
    }

    /**
     * Unpack data from binary string, with checking that the operation
     * was successful.
     * 
     * @param string $format the format code
     * @param string $data the packed data
     * @return mixed
     * @throws CBORException
     */
    protected function unpack(string $format, string $data) {
        $result = unpack($format, $data);
        if ($result === false) throw new CBORException('Cannot unpack binary string into expected format: ' . $format);
        return $result[1];
    }
}

?>
