<?php

namespace SimpleJWT;

use SimpleJWT\Util\CBOR\CBOR;
use SimpleJWT\Util\CBOR\DataItem;
use PHPUnit\Framework\TestCase;

class CBORTest extends TestCase {
    function testDecodeInt() {
        $cbor = new CBOR();

        $this->assertEquals(23, $cbor->decode(base64_decode('Fw==')));
        $this->assertEquals(24, $cbor->decode(base64_decode('GBg=')));
        $this->assertEquals(1000000, $cbor->decode(base64_decode('GgAPQkA=')));
        $this->assertEquals(-1, $cbor->decode(base64_decode('IA==')));
        $this->assertEquals(-100, $cbor->decode(base64_decode('OGM=')));
    }

    function testDecodeFloat() {
        $cbor = new CBOR();
        // float16
        $this->assertEquals(0.0, $cbor->decode(base64_decode('+QAA')));

        // float32
        $this->assertEquals(100000.0, $cbor->decode(base64_decode('+kfDUAA=')));

        // float64
        $this->assertEquals(1.1, $cbor->decode(base64_decode('+z/xmZmZmZma')));
    }

    function testDecodeSimpleValues() {
        $cbor = new CBOR();

        $this->assertFalse($cbor->decode(base64_decode('9A==')));
        $this->assertTrue($cbor->decode(base64_decode('9Q==')));
        $this->assertNull($cbor->decode(base64_decode('9g==')));

        $undefined = $cbor->decode(base64_decode('9w=='), DataItem::DECODE_MIXED);
        $this->assertEquals(DataItem::UNDEFINED_TYPE, $undefined->getType());

        $simple = $cbor->decode(base64_decode('8A=='), DataItem::DECODE_MIXED);
        $this->assertEquals(DataItem::SIMPLE_VALUE_TYPE, $simple->getType());
        $this->assertEquals(16, $simple->getValue());

        $simple2 = $cbor->decode(base64_decode('+P8='), DataItem::DECODE_MIXED);
        $this->assertEquals(DataItem::SIMPLE_VALUE_TYPE, $simple2->getType());
        $this->assertEquals(255, $simple2->getValue());
    }

    function testDecodeString() {
        $cbor = new CBOR();

        $this->assertEquals("\x01\x02\x03\x04", $cbor->decode(base64_decode('RAECAwQ=')));
        $this->assertEquals("\"\\", $cbor->decode(base64_decode('YiJc')));
    }

    function testDecodeList() {
        $cbor = new CBOR();

        $this->assertEquals([], $cbor->decode(base64_decode('gA==')));
        $this->assertEquals([1, 2, 3], $cbor->decode(base64_decode('gwECAw==')));
        $this->assertEquals([1, [2, 3], [4, 5]], $cbor->decode(base64_decode('gwGCAgOCBAU=')));
    }

    function testDecodeMap() {
        $cbor = new CBOR();

        $this->assertEquals([], $cbor->decode(base64_decode('oA==')));

        $v = $cbor->decode(base64_decode('pWFhYUFhYmFCYWNhQ2FkYURhZWFF'));
        $this->assertEquals('A', $v['a']);
    }

    function testDecodeTaggedValue() {
        $cbor = new CBOR();
        // bstr tagged 2
        $item = $cbor->decode(base64_decode('wkkBAAAAAAAAAAA='), DataItem::DECODE_OBJECT);
        $this->assertEquals(2, $item->getTag());
        $this->assertEquals('AQAAAAAAAAAA', base64_encode($item->getValue()));
    }
}

?>