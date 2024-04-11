<?php

use SimpleJWT\Keys\KeyFactory;
use SimpleJWT\Keys\RSAKey;
use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\SymmetricKey;
use PHPUnit\Framework\TestCase;

class KeyFactoryTest extends TestCase {
    public function testPEMRSA() {
        $pem = file_get_contents('rsa_private.pem');
        $key = KeyFactory::create($pem, 'pem');
        $this->assertInstanceOf(RSAKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("p8wHcPeYsIbQBwFg-mUXIFjZI-b1gQJuNoGboa3ub7KMVjmob9c4mOqc8j2u9cMS6PLnqGMIiM2H1HVDZSwZs6kS7Kq942uNBsut2cHy-PZd5Jq3cWIoQZwnhrjg_OfwbJugYeGe0Orub8J42qyT8HuhLX65Q6iSSf_3bo1Rr2M", $key_data['n']);
        $this->assertEquals("Wxts7umA_lg0m5kkDtDUvbuAKv48TtADB5VX63GFBSDtEeQ8kH1LPbwle2ICnW5N1i4NmmArQhxWpAUHkudfDExa9fZf5wUtsDlw8zNhzoDKqtw50D1BhWCfYO19IobTL-x3RJmPAepK5IH8ZYfGbQD2ZEwN0WF2I8sBg4Pu6Q", $key_data['d']);
        $this->assertEquals("2sUA6n24v51XMCk_H3WKTELYfEyWzdr6yI3a8xNol8RlLNcjr9NxthPWkOGY6uT1JAbDgBNsiPQXpAiOdRD5FQ", $key_data['p']);
        $this->assertEquals("xFpV_GjvAlkzeElY_fb5AWgV9_APIfyuo3NxqmvaRTIUyatsHdrUNE0jsOTJF-2uZZ818sbHltDOb-x3_3y0lw", $key_data['q']);

        $pem = file_get_contents('rsa_public.pem');
        $key = KeyFactory::create($pem, 'pem');
        $this->assertInstanceOf(RSAKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertTrue($key->isPublic());
        $this->assertEquals("p8wHcPeYsIbQBwFg-mUXIFjZI-b1gQJuNoGboa3ub7KMVjmob9c4mOqc8j2u9cMS6PLnqGMIiM2H1HVDZSwZs6kS7Kq942uNBsut2cHy-PZd5Jq3cWIoQZwnhrjg_OfwbJugYeGe0Orub8J42qyT8HuhLX65Q6iSSf_3bo1Rr2M", $key_data['n']);
    }


    public function testPEMEC() {
        $pem = file_get_contents('ec_private.pem');
        $key = KeyFactory::create($pem, 'auto');
        $this->assertInstanceOf(ECKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("IUN-eG7WkRmqa5xa_agso36vn0ZLJ7EokYyPK64M1ww", $key_data['d']);
        $this->assertEquals("V_Go0coP2q7BktWwkkHBVgVMCt5gpIyegCccpfoGPy4", $key_data['x']);
        $this->assertEquals("aEPjI2pjfCwPeoh2KykOpVPLSUJ9tGHH5ER-DGYjt_g", $key_data['y']);

        $pem = file_get_contents('ec_public.pem');
        $key = KeyFactory::create($pem, 'auto');
        $this->assertInstanceOf(ECKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertTrue($key->isPublic());
        $this->assertEquals("V_Go0coP2q7BktWwkkHBVgVMCt5gpIyegCccpfoGPy4", $key_data['x']);
        $this->assertEquals("aEPjI2pjfCwPeoh2KykOpVPLSUJ9tGHH5ER-DGYjt_g", $key_data['y']);
    }

    public function testPEMEC_secp256k1() {
        $pem = file_get_contents('ec_secp256k1_private.pem');
        $key = KeyFactory::create($pem, 'pem');
        $this->assertInstanceOf(ECKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("jA_zoAn0BhF0M7x8A3zZtWuFXI9U-A1jAGXjTKHsMkY", $key_data['d']);
        $this->assertEquals("QGVPYUfFqCwBeaapsTbrtQZFU5h0EXBO8iEzH3pUz-c", $key_data['x']);
        $this->assertEquals("3BZVYSHcdZMkWtnnenhAiCXdWJyVGEMKMECIdzVD11U", $key_data['y']);

        $pem = file_get_contents('ec_secp256k1_public.pem');
        $key = KeyFactory::create($pem, 'pem');
        $this->assertInstanceOf(ECKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertTrue($key->isPublic());
        $this->assertEquals("QGVPYUfFqCwBeaapsTbrtQZFU5h0EXBO8iEzH3pUz-c", $key_data['x']);
        $this->assertEquals("3BZVYSHcdZMkWtnnenhAiCXdWJyVGEMKMECIdzVD11U", $key_data['y']);
    }

    public function testSymmetric() {
        $bin = file_get_contents('symmetric.bin');
        $key = KeyFactory::create($bin, 'bin');
        $this->assertInstanceOf(SymmetricKey::class, $key);
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("VGhpcyBpcyBhIHN0cmluZyB0byBiZSBpbnRlcnByZXRlZCBhcyBhIGJ5dGVzdHJlYW0gdG8gYmUgdXNlZCBhcyBzeW1tZXRyaWMga2V5IDMuMTQxNTkyNjUzNTg5NzkzMjM4NDYyNjQzMzgzMjc5NTAyODg0MTk3MTY5Mzk5Mzc", $key_data['k']);
    }

    function testInvalidJSONKey() {
        $invalid = '{ "kty": "oct", "k": "VGhpcyBpcyBhIHN0cmluZyB0byBiZSBpbnRlcnByZXRlZCBhcyBhIGJ5dGVzdHJlYW0gdG8gYmUgdXNlZCBhcyBzeW1tZXRyaWMga2V5IDMuMTQxNTkyNjUzNTg5NzkzMjM4NDYyNjQzMzgzMjc5NTAyODg0MTk3MTY5Mzk5Mzc=", }';

        $this->expectException('SimpleJWT\Keys\KeyException');
        $this->expectExceptionMessage('Incorrect key data format - malformed JSON');
        $key = KeyFactory::create($invalid, 'json');
    }
}
?>
