<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

/*
 * Test vectors are sourced from
 * https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
 */
class AESGCMTest extends TestCase {
    protected function isAlgAvailable($alg) {
        $aesgcm = new AESGCM(null);
        if (!in_array($alg, $aesgcm->getSupportedAlgs())) {
            $this->markTestSkipped('Alg not available: ' . $alg);
            return false;
        } else {
            return true;
        }
    }

    protected function hex2base64url($hex) {
        return Util::base64url_encode(pack('H*', $hex));
    }

    function testA128GCMEncrypt() {
        if (!$this->isAlgAvailable('A128GCM')) return;

        // [Keylen = 128] [IVlen = 96] [PTlen = 128] [AADlen = 0] [Taglen = 128] [Count = 0]
        $cek = hex2bin('7fddb57453c241d03efbed3ac44e371c');
        $plaintext = hex2bin('d5de42b461646c255c87bd2962d3b9a2');
        $iv = $this->hex2base64url('ee283a3fc75575e33efd4887');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->hex2base64url('2ccda4a5415cb91e135c2a0f78c9b2fd'), $results['ciphertext']);
        $this->assertEquals($this->hex2base64url('b36d1df9b9d5e596f83e8b7f52971cb3'), $results['tag']);
    }

    function testA128GCMDecrypt() {
        if (!$this->isAlgAvailable('A128GCM')) return;

        // [Keylen = 128] [IVlen = 96] [PTlen = 128] [AADlen = 0] [Taglen = 128] [Count = 0]
        $cek = hex2bin('e98b72a9881a84ca6b76e0f43e68647a');
        $ciphertext = $this->hex2base64url('5a3c1cf1985dbb8bed818036fdd5ab42');
        $tag = $this->hex2base64url('23c7ab0f952b7091cd324835043b5eb5');
        $iv = $this->hex2base64url('8b23299fde174053f3d652ba');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

        $this->assertEquals(hex2bin('28286a321293253c3e0aa2704a278032'), $results);
    }

    /**
     * @expectedException SimpleJWT\Crypt\CryptException
     */
    function testA128GCMIncorrectTag() {
        if (!$this->isAlgAvailable('A128GCM')) return;

        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\Crypt\CryptException');
        }
        
        $cek = hex2bin('e98b72a9881a84ca6b76e0f43e68647a');
        $ciphertext = $this->hex2base64url('5a3c1cf1985dbb8bed818036fdd5ab42');
        $tag = $this->hex2base64url('23c7ab0f952b7091cd324835043b5eb6');
        $iv = $this->hex2base64url('8b23299fde174053f3d652ba');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);
    }

    function testA192Encrypt() {
        if (!$this->isAlgAvailable('A192GCM')) return;
        
        // [Keylen = 192] [IVlen = 96] [PTlen = 128] [AADlen = 0] [Taglen = 128] [Count = 0]
        $cek = hex2bin('fbc0b4c56a714c83217b2d1bcadd2ed2e9efb0dcac6cc19f');
        $plaintext = hex2bin('d2ae38c4375954835d75b8e4c2f9bbb4');
        $iv = $this->hex2base64url('5f4b43e811da9c470d6a9b01');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->hex2base64url('69482957e6be5c54882d00314e0259cf'), $results['ciphertext']);
        $this->assertEquals($this->hex2base64url('191e9f29bef63a26860c1e020a21137e'), $results['tag']);
    }

    function testA192Decrypt() {
        if (!$this->isAlgAvailable('A192GCM')) return;
        
        // [Keylen = 192] [IVlen = 96] [PTlen = 128] [AADlen = 0] [Taglen = 128] [Count = 0]
        $cek = hex2bin('7a7c5b6a8a9ab5acae34a9f6e41f19a971f9c330023c0f0c');
        $ciphertext = $this->hex2base64url('132ae95bd359c44aaefa6348632cafbd');
        $tag = $this->hex2base64url('19d7c7d5809ad6648110f22f272e7d72');
        $iv = $this->hex2base64url('aa4c38bf587f94f99fee77d5');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

        $this->assertEquals(hex2bin('99ae6f479b3004354ff18cd86c0b6efb'), $results);
    }

    /**
     * @expectedException SimpleJWT\Crypt\CryptException
     */
    function testA192GCMIncorrectTag() {
        if (!$this->isAlgAvailable('A192GCM')) return;
        
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\Crypt\CryptException');
        }
        
        $cek = hex2bin('7a7c5b6a8a9ab5acae34a9f6e41f19a971f9c330023c0f0c');
        $ciphertext = $this->hex2base64url('132ae95bd359c44aaefa6348632cafbd');
        $tag = $this->hex2base64url('19d7c7d5809ad6648110f22f272e7d73');
        $iv = $this->hex2base64url('aa4c38bf587f94f99fee77d5');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);
    }

    function testA256Encrypt() {
        if (!$this->isAlgAvailable('A256GCM')) return;
        
        // [Keylen = 256] [IVlen = 96] [PTlen = 128] [AADlen = 0] [Taglen = 128] [Count = 0]
        $cek = hex2bin('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22');
        $plaintext = hex2bin('2db5168e932556f8089a0622981d017d');
        $iv = $this->hex2base64url('0d18e06c7c725ac9e362e1ce');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->hex2base64url('fa4362189661d163fcd6a56d8bf0405a'), $results['ciphertext']);
        $this->assertEquals($this->hex2base64url('d636ac1bbedd5cc3ee727dc2ab4a9489'), $results['tag']);
    }

    function testA256Decrypt() {
        if (!$this->isAlgAvailable('A256GCM')) return;
        
        // [Keylen = 256] [IVlen = 96] [PTlen = 128] [AADlen = 0] [Taglen = 128] [Count = 0]
        $cek = hex2bin('4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8');
        $ciphertext = $this->hex2base64url('d2c78110ac7e8f107c0df0570bd7c90c');
        $tag = $this->hex2base64url('c26a379b6d98ef2852ead8ce83a833a7');
        $iv = $this->hex2base64url('473360e0ad24889959858995');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

        $this->assertEquals(hex2bin('7789b41cb3ee548814ca0b388c10b343'), $results);
    }

    /**
     * @expectedException SimpleJWT\Crypt\CryptException
     */
    function testA256GCMIncorrectTag() {
        if (!$this->isAlgAvailable('A256GCM')) return;
        
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\Crypt\CryptException');
        }

        $cek = hex2bin('4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8');
        $ciphertext = $this->hex2base64url('d2c78110ac7e8f107c0df0570bd7c90c');
        $tag = $this->hex2base64url('c26a379b6d98ef2852ead8ce83a833a8');
        $iv = $this->hex2base64url('473360e0ad24889959858995');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);
    }
}
?>
