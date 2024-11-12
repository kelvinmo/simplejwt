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

namespace SimpleJWT\Util\CBOR;

use \SimpleJWT\Util\Util;
use \InvalidArgumentException;

/**
 * An object representing a CBOR data item.
 * 
 * An CBOR data item contains the following components:
 * 
 * - the *type*, which consists of:
 *     - the major type as defined in the CBOR specification
 *     - for major type 7, the value
 * - the *value*, which is stored as a native PHP value (see below)
 * - optionally, the *tag*
 * 
 * The following sets out the native PHP value for each CBOR type.
 * 
 * - `uint`, `nint`: `int` (or a `GMP` object)
 * 
 * - `bstr`: `string`
 * - `tstr`: `string`
 * - list: `array`
 * - map: `array`
 * - simple values:
 *      - `bool`: `bool`
 *      - `null`: `null`
 *      - `undefined`: `null`
 *      - others: `int`
 * - `float`: `float`
 *  
 * It can be seen that ambiguous when converting native PHP types back
 * to CBOR.  Rules:
 * 
 * - A PHP `null` will be converted to `null` rather than `undefined`
 * - A PHP positive integer will be converted to `uint` rather than a simple value
 */
class DataItem {

    const DECODE_NATIVE = 0;
    const DECODE_CONVERT_BSTR = 1;
    const DECODE_MIXED = 2;
    const DECODE_OBJECT = -1;

    // Type = major type or object
    const UINT_TYPE = 0b00000000;
    const NINT_TYPE = 0b00100000;
    const BSTR_TYPE = 0b01000000;
    const TSTR_TYPE = 0b01100000;
    const LIST_TYPE = 0b10000000;
    const MAP_TYPE = 0b10100000;
    const TAG_TYPE = 0b11000000;
    const OTHER_MAJOR_TYPE = 0b11100000;

    const FALSE_TYPE = self::OTHER_MAJOR_TYPE + 20;
    const TRUE_TYPE = self::OTHER_MAJOR_TYPE + 21;
    const NULL_TYPE = self::OTHER_MAJOR_TYPE + 22;
    const UNDEFINED_TYPE = self::OTHER_MAJOR_TYPE + 23;
    const SIMPLE_VALUE_TYPE = self::OTHER_MAJOR_TYPE + 24;  // Includes OTHER_MAJOR_TYPE + 0..19
    const FLOAT16_TYPE = self::OTHER_MAJOR_TYPE + 25;
    const FLOAT32_TYPE = self::OTHER_MAJOR_TYPE + 26;
    const FLOAT64_TYPE = self::OTHER_MAJOR_TYPE + 27;
    const BREAK_CODE = self::OTHER_MAJOR_TYPE + 31;

    // https://www.rfc-editor.org/rfc/rfc8949.html#name-self-described-cbor
    const CBOR_MAGIC_TAG = 55799;

    /** @var array<int, string> $simple_types */
    static $simple_types = [
        self::FALSE_TYPE => 'false',
        self::TRUE_TYPE => 'true',
        self::NULL_TYPE => 'null',
        self::UNDEFINED_TYPE => 'undefined'
    ];

    /** @var int $type */
    protected $type;

    /** @var mixed $value */
    protected $value;

    /** @var int $tag */
    protected $tag = null;

    /**
     * Creates a CBOR object
     * 
     * @param int $type the type
     * @param mixed $value the native PHP value
     * @param int $tag the tag number (i.e. excluding the class and constructed bit masks)
     */
    function __construct(int $type, $value, int $tag = null) {
        $this->type = $type;
        $this->value = $value;
        $this->tag = $tag;
    }

    /**
     * Creates a value representing an integer.
     * 
     * If a string is given as the argument for `$value`, it is treated as a binary string
     * and will be converted to a `GMP` object using the `gmp_import()` function.
     * 
     * @param int|string|\GMP $value
     * @return DataItem
     */
    static public function int($value): self {
        if (is_string($value)) {
            $value = gmp_import($value);
        }
        if ($value instanceof \GMP) {
            $sign = gmp_sign($value);
        } else {
            $sign = ($value < 0) ? -1 : 1;
        }
        return new self(($sign == -1) ? static::NINT_TYPE : static::UINT_TYPE, $value);
    }

    /**
     * Creates a value representing a floating point value.
     * 
     * @param float $value
     * @return DataItem
     */
    static public function float($value): self {
        return new self(static::FLOAT64_TYPE, $value);
    }

    /**
     * Creates a value representing a byte string.
     * 
     * @param string $value
     * @return DataItem
     */
    static public function bstr(string $value): self {
        return new self(static::BSTR_TYPE, $value);
    }

    /**
     * Creates a value representing a text string.
     * 
     * The text string must already be encoded in UTF-8.
     * 
     * @param string $value
     * @return DataItem
     */
    static public function tstr(string $value): self {
        return new self(static::TSTR_TYPE, $value);
    }

    /**
     * Creates a value representing a boolean.
     * 
     * @param bool $value
     * @return DataItem
     */
    static public function bool(bool $value): self {
        if ($value === true) {
            return new self(static::TRUE_TYPE, $value);
        } else {
            return new self(static::FALSE_TYPE, $value);
        }
    }

    /**
     * Creates a value representing a null.
     * 
     * @return DataItem
     */
    static public function null(): self {
        return new self(static::NULL_TYPE, null);
    }

    /**
     * Creates a value representing an undefined value.
     * 
     * @return DataItem
     */
    static public function undefined(): self {
        return new self(static::UNDEFINED_TYPE, null);
    }

    /**
     * Creates a value representing an undefined value.
     * 
     * @param int $value
     * @return DataItem
     */
    static public function simple(int $value): self {
        return new self(static::SIMPLE_VALUE_TYPE, $value);
    }

    /**
     * Creates a value representing a sequence.
     * 
     * @param array<int, mixed> $value
     * @return DataItem
     */
    static public function list(array $value): self {
        if (!Util::array_is_list($value)) {
            throw new InvalidArgumentException('Not an array');
        }
        return new self(static::LIST_TYPE, $value);
    }

    /**
     * Creates a value representing a map.
     * 
     * @param array<mixed, mixed> $value
     * @return DataItem
     */
    static public function map(array $value): self {
        if (Util::array_is_list($value)) {
            throw new InvalidArgumentException('Not an associative array');
        }
        return new self(static::MAP_TYPE, $value);
    }

    /**
     * @param mixed $value
     * @return DataItem
     */
    static public function default($value): self {
        if ($value instanceof DataItem) {
            return $value;
        } elseif (is_array($value)) {
            if (Util::array_is_list($value)) {
                return static::list($value);
            } else {
                return static::map($value);
            }
        } elseif (is_bool($value)) {
            return static::bool($value);
        } elseif (is_float($value)) {
            return static::float($value);
        } elseif (is_int($value) || ($value instanceof \GMP)) {
            return static::int($value);
        } elseif (is_string($value)) {
            return static::tstr($value);
        } elseif (is_null($value)) {
            return static::null();
        } else {
            throw new CBORException('Cannot represent as CBOR value');
        }
    }

    /**
     * Returns the value of the data item.
     * 
     * The type of value that is returned is determined by the $mode parameter.
     * If the value is a map or a list, then a PHP array will be returned, with
     * the type all the items determined by the $mode parameter.
     * 
     * $mode can take one of the following values:
     * 
     * - `self::DECODE_NATIVE` - this will always return a native PHP
     *   value
     * - `self::DECODE_CONVERT_BSTR` - similar to `DECODE_NATIVE`, except that
     *   binary strings are converted to base64url
     * - `self::DECODE_MIXED` - returns a native PHP value, unless it is a
     *   binary string (`bstr`), a simple value, an undefined item, or contains a tag
     *   (other than 55799, which identifies a CBOR stream), in which case a DataItem is returned
     * - `self::DECODE_OBJECT` - returns a DataItem, or an array of
     *   DataItem instances
     * 
     * @param int $mode
     * @return mixed|DataItem|array<mixed, DataItem>
     */
    public function getValue(int $mode = self::DECODE_NATIVE) {
        if (is_array($this->value)) {
            $results = [];
            foreach ($this->value as $k => $v) {
                if ($v instanceof DataItem) {
                    $results[$k] = $v->getValue($mode);
                } elseif ($mode == self::DECODE_OBJECT) {
                    $results[$k] = self::default($v);
                } else {
                    $results[$k] = $v;
                }
            }
            return $results;
        } else {
            switch ($mode) {
                case self::DECODE_OBJECT:
                    return $this;
                case self::DECODE_NATIVE:
                    return $this->value;
                case self::DECODE_CONVERT_BSTR:
                    if ($this->type == self::BSTR_TYPE) {
                        return Util::base64url_encode($this->value);
                    } else {
                        return $this->value;
                    }
                case self::DECODE_MIXED:
                    if (($this->type == self::BSTR_TYPE)
                        || ($this->type == self::UNDEFINED_TYPE)
                        || ($this->type == self::SIMPLE_VALUE_TYPE)
                        || (($this->tag != null) && ($this->tag != self::CBOR_MAGIC_TAG))) {
                        // These are ambiguous types
                        return $this;
                    } else {
                        return $this->value;
                    }
                default:
                    throw new \InvalidArgumentException('Invalid decoding mode specified');
            }
        }
    }

    /**
     * Returns the tag
     * 
     * @return int|null
     */
    public function getTag(): ?int {
        return $this->tag;
    }

    /**
     * Sets the tag
     * 
     * @param int $tag the tag value
     * @return void
     */
    public function setTag(int $tag) {
        $this->tag = $tag;
    }

    /**
     * Returns the type
     * 
     * @return int
     */
    public function getType(): int {
        return $this->type;
    }

    /**
     * Returns the major type
     * 
     * @return int
     */
    public function getMajorType(): int {
        return $this->type >> 5;
    }

    /**
     * Returns a diagnostic representation of the value
     * 
     * @param int $indent
     * @return string
     */
    protected function prettyPrint(int $indent = 0): string {
        $result = '';
        if (isset(self::$simple_types[$this->type])) {
            $result .= self::$simple_types[$this->type];
        } elseif ($this->type == self::LIST_TYPE) {
            $contents = array_map(function($x) use ($indent) { return $x->prettyPrint($indent); }, $this->value);
            $result .= '[' . implode(', ', $contents) . ']';
        } elseif ($this->type == self::MAP_TYPE) {
            $contents = array_map(function($k, $v) use ($indent) { 
                /** @var DataItem $v */
                return str_pad('', $indent) . ((is_numeric($k)) ? $k : '"' . json_encode($k) . '"') . ': ' . $v->prettyPrint(); 
            }, array_keys($this->value), array_values($this->value));
            $result .= "{\n" . implode(",\n", $contents) . "\n" . str_pad('', $indent) . "}";
        } elseif ($this->type == self::BSTR_TYPE) {
            $result .= 'b64\'' . base64_encode($this->value) . '\'';
        } elseif ($this->type == self::TSTR_TYPE) {
            $result .= '\'' . json_encode($this->value) . '\'';
        } elseif ($this->type == self::SIMPLE_VALUE_TYPE) {
            $result .= 'simple(' . $this->value . ')';
        } elseif ($this->value instanceof \GMP) {
            $result .= gmp_strval($this->value);
        } else {
            $result .= $this->value;
        }

        if ($this->tag != null) {
            $result = $this->tag . '(' . $result . ')';
        }

        return str_pad('', $indent) . $result;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string {
        return $this->prettyPrint();
    }
}

?>
