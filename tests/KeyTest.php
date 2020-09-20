<?php

use SimpleJWT\Keys\RSAKey;
use SimpleJWT\Keys\ECKey;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase {
    public function testRSA() {
        $pem = file_get_contents('rsa_private.pem');
        $key = new RSAKey($pem, 'pem');
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("p8wHcPeYsIbQBwFg-mUXIFjZI-b1gQJuNoGboa3ub7KMVjmob9c4mOqc8j2u9cMS6PLnqGMIiM2H1HVDZSwZs6kS7Kq942uNBsut2cHy-PZd5Jq3cWIoQZwnhrjg_OfwbJugYeGe0Orub8J42qyT8HuhLX65Q6iSSf_3bo1Rr2M", $key_data['n']);
        $this->assertEquals("AFsbbO7pgP5YNJuZJA7Q1L27gCr-PE7QAweVV-txhQUg7RHkPJB9Sz28JXtiAp1uTdYuDZpgK0IcVqQFB5LnXwxMWvX2X-cFLbA5cPMzYc6AyqrcOdA9QYVgn2DtfSKG0y_sd0SZjwHqSuSB_GWHxm0A9mRMDdFhdiPLAYOD7uk", $key_data['d']);
        $this->assertEquals("2sUA6n24v51XMCk_H3WKTELYfEyWzdr6yI3a8xNol8RlLNcjr9NxthPWkOGY6uT1JAbDgBNsiPQXpAiOdRD5FQ", $key_data['p']);
        $this->assertEquals("xFpV_GjvAlkzeElY_fb5AWgV9_APIfyuo3NxqmvaRTIUyatsHdrUNE0jsOTJF-2uZZ818sbHltDOb-x3_3y0lw", $key_data['q']);

        $pem = file_get_contents('rsa_public.pem');
        $key = new RSAKey($pem, 'pem');
        $key_data = $key->getKeyData();
        $this->assertTrue($key->isPublic());
        $this->assertEquals("p8wHcPeYsIbQBwFg-mUXIFjZI-b1gQJuNoGboa3ub7KMVjmob9c4mOqc8j2u9cMS6PLnqGMIiM2H1HVDZSwZs6kS7Kq942uNBsut2cHy-PZd5Jq3cWIoQZwnhrjg_OfwbJugYeGe0Orub8J42qyT8HuhLX65Q6iSSf_3bo1Rr2M", $key_data['n']);
    }


    public function testEC() {
        $pem = file_get_contents('ec_private.pem');
        $key = new ECKey($pem, 'pem');
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("IUN-eG7WkRmqa5xa_agso36vn0ZLJ7EokYyPK64M1ww", $key_data['d']);
        $this->assertEquals("V_Go0coP2q7BktWwkkHBVgVMCt5gpIyegCccpfoGPy4", $key_data['x']);
        $this->assertEquals("aEPjI2pjfCwPeoh2KykOpVPLSUJ9tGHH5ER-DGYjt_g", $key_data['y']);

        $pem = file_get_contents('ec_public.pem');
        $key = new ECKey($pem, 'pem');
        $key_data = $key->getKeyData();
        $this->assertTrue($key->isPublic());
        $this->assertEquals("V_Go0coP2q7BktWwkkHBVgVMCt5gpIyegCccpfoGPy4", $key_data['x']);
        $this->assertEquals("aEPjI2pjfCwPeoh2KykOpVPLSUJ9tGHH5ER-DGYjt_g", $key_data['y']);
    }

    public function testEC_secp256k1() {
        $pem = file_get_contents('ec_secp256k1_private.pem');
        $key = new ECKey($pem, 'pem');
        $key_data = $key->getKeyData();
        $this->assertFalse($key->isPublic());
        $this->assertEquals("jA_zoAn0BhF0M7x8A3zZtWuFXI9U-A1jAGXjTKHsMkY", $key_data['d']);
        $this->assertEquals("QGVPYUfFqCwBeaapsTbrtQZFU5h0EXBO8iEzH3pUz-c", $key_data['x']);
        $this->assertEquals("3BZVYSHcdZMkWtnnenhAiCXdWJyVGEMKMECIdzVD11U", $key_data['y']);

        $pem = file_get_contents('ec_secp256k1_public.pem');
        $key = new ECKey($pem, 'pem');
        $key_data = $key->getKeyData();
        $this->assertTrue($key->isPublic());
        $this->assertEquals("QGVPYUfFqCwBeaapsTbrtQZFU5h0EXBO8iEzH3pUz-c", $key_data['x']);
        $this->assertEquals("3BZVYSHcdZMkWtnnenhAiCXdWJyVGEMKMECIdzVD11U", $key_data['y']);

    }
}
?>
