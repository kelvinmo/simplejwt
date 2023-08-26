<?php

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class AESGCMKeyWrapTest extends TestCase {
    protected function isAlgAvailable($alg) {
        $aesgcm = new AESGCMKeyWrap(null);
        if (!in_array($alg, $aesgcm->getSupportedAlgs())) {
            $this->markTestSkipped('Alg not available: ' . $alg);
            return false;
        } else {
            return true;
        }
    }

    protected function getKeySet($kek) {
        return \SimpleJWT\Keys\KeySet::createFromSecret($kek, 'bin');
    }

    protected function hex2base64url($hex) {
        return Util::base64url_encode(pack('H*', $hex));
    }

    function testA128GCMKeyWrap() {
        if (!$this->isAlgAvailable('A128GCMKW')) return;

        $iv_hex = 'ee283a3fc75575e33efd4887';

        $builder = $this->getMockBuilder('SimpleJWT\Crypt\KeyManagement\AESGCMKeyWrap');
        if (method_exists($builder, 'setMethods')) {
            $stub = $builder->setConstructorArgs(['A128GCMKW'])
            ->setMethods(['generateIV'])
            ->getMock();
        } else {
            $stub = $builder->setConstructorArgs(['A128GCMKW'])
            ->onlyMethods(['generateIV'])
            ->getMock();
        }
        $stub->method('generateIV')->willReturn(hex2bin($iv_hex));

        $headers = [];

        $key = hex2bin('d5de42b461646c255c87bd2962d3b9a2');
        $set = $this->getKeySet(hex2bin('7fddb57453c241d03efbed3ac44e371c'));
        $encrypted_key = $stub->encryptKey($key, $set, $headers);

        $this->assertEquals($this->hex2base64url('2ccda4a5415cb91e135c2a0f78c9b2fd'), $encrypted_key);
        $this->assertEquals($this->hex2base64url($iv_hex), $headers['iv']);
        $this->assertEquals($this->hex2base64url('b36d1df9b9d5e596f83e8b7f52971cb3'), $headers['tag']);

        $decrypted_key = $stub->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA192GCMKeyWrap() {
        if (!$this->isAlgAvailable('A192GCMKW')) return;

        $iv_hex = '5f4b43e811da9c470d6a9b01';

        $builder = $this->getMockBuilder('SimpleJWT\Crypt\KeyManagement\AESGCMKeyWrap');
        if (method_exists($builder, 'setMethods')) {
            $stub = $builder->setConstructorArgs(['A192GCMKW'])
            ->setMethods(['generateIV'])
            ->getMock();
        } else {
            $stub = $builder->setConstructorArgs(['A192GCMKW'])
            ->onlyMethods(['generateIV'])
            ->getMock();
        }
        $stub->method('generateIV')->willReturn(hex2bin($iv_hex));

        $headers = [];

        $key = hex2bin('d2ae38c4375954835d75b8e4c2f9bbb4');
        $set = $this->getKeySet(hex2bin('fbc0b4c56a714c83217b2d1bcadd2ed2e9efb0dcac6cc19f'));
        $encrypted_key = $stub->encryptKey($key, $set, $headers);

        $this->assertEquals($this->hex2base64url('69482957e6be5c54882d00314e0259cf'), $encrypted_key);
        $this->assertEquals($this->hex2base64url($iv_hex), $headers['iv']);
        $this->assertEquals($this->hex2base64url('191e9f29bef63a26860c1e020a21137e'), $headers['tag']);

        $decrypted_key = $stub->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA256GCMKeyWrap() {
        if (!$this->isAlgAvailable('A256GCMKW')) return;

        $iv_hex = '0d18e06c7c725ac9e362e1ce';

        $builder = $this->getMockBuilder('SimpleJWT\Crypt\KeyManagement\AESGCMKeyWrap');
        if (method_exists($builder, 'setMethods')) {
            $stub = $builder->setConstructorArgs(['A256GCMKW'])
            ->setMethods(['generateIV'])
            ->getMock();
        } else {
            $stub = $builder->setConstructorArgs(['A256GCMKW'])
            ->onlyMethods(['generateIV'])
            ->getMock();
        }
        $stub->method('generateIV')->willReturn(hex2bin($iv_hex));

        $headers = [];

        $key = hex2bin('2db5168e932556f8089a0622981d017d');
        $set = $this->getKeySet(hex2bin('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22'));
        $encrypted_key = $stub->encryptKey($key, $set, $headers);

        $this->assertEquals($this->hex2base64url('fa4362189661d163fcd6a56d8bf0405a'), $encrypted_key);
        $this->assertEquals($this->hex2base64url($iv_hex), $headers['iv']);
        $this->assertEquals($this->hex2base64url('d636ac1bbedd5cc3ee727dc2ab4a9489'), $headers['tag']);

        $decrypted_key = $stub->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }
}
?>