<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class AESKeyWrapTest extends TestCase {

    protected function getKeySet($kek) {
        return \SimpleJWT\Keys\KeySet::createFromSecret($kek, 'bin');
    }

    protected function hex2base64url($hex) {
        return Util::base64url_encode(pack('H*', $hex));
    }

    function testA128KWWith128Key() {
        $kek = pack('H*', '000102030405060708090A0B0C0D0E0F');
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new AESKeyWrap('A128KW');
        $set = $this->getKeySet($kek);
        $headers = [];
        $encrypted_key = $alg->encryptKey($key, $set, $headers);
        $this->assertEquals($this->hex2base64url('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'), $encrypted_key);

        $decrypted_key = $alg->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA192KWWith128Key() {
        $kek = pack('H*', '000102030405060708090A0B0C0D0E0F1011121314151617');
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new AESKeyWrap('A192KW');
        $set = $this->getKeySet($kek);
        $headers = [];
        $encrypted_key = $alg->encryptKey($key, $set, $headers);
        $this->assertEquals($this->hex2base64url('96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D'), $encrypted_key);

        $decrypted_key = $alg->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA256KWWith128Key() {
        $kek = pack('H*', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new AESKeyWrap('A256KW');
        $set = $this->getKeySet($kek);
        $headers = [];
        $encrypted_key = $alg->encryptKey($key, $set, $headers);
        $this->assertEquals($this->hex2base64url('64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7'), $encrypted_key);

        $decrypted_key = $alg->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA192KWWith192Key() {
        $kek = pack('H*', '000102030405060708090A0B0C0D0E0F1011121314151617');
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF0001020304050607');

        $alg = new AESKeyWrap('A192KW');
        $set = $this->getKeySet($kek);
        $headers = [];
        $encrypted_key = $alg->encryptKey($key, $set, $headers);
        $this->assertEquals($this->hex2base64url('031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2'), $encrypted_key);

        $decrypted_key = $alg->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA256KWWith192Key() {
        $kek = pack('H*', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF0001020304050607');

        $alg = new AESKeyWrap('A256KW');
        $set = $this->getKeySet($kek);
        $headers = [];
        $encrypted_key = $alg->encryptKey($key, $set, $headers);
        $this->assertEquals($this->hex2base64url('A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1'), $encrypted_key);

        $decrypted_key = $alg->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testA256KWWith246Key() {
        $kek = pack('H*', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $alg = new AESKeyWrap('A256KW');
        $set = $this->getKeySet($kek);
        $headers = [];
        $encrypted_key = $alg->encryptKey($key, $set, $headers);
        $this->assertEquals($this->hex2base64url('28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'), $encrypted_key);

        $decrypted_key = $alg->decryptKey($encrypted_key, $set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }
}
?>
