<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;

class AESGCMTest extends \PHPUnit_Framework_TestCase {

    protected function base64url($base64) {
        return Util::base64url_encode(base64_decode($base64));
    }

    function testA128GCMEncrypt() {
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAA==');
        $plaintext = base64_decode('AAAAAAAAAAAAAAAA');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('A4jazmC2o5LzKMK5'), $results['ciphertext']);
        $this->assertEquals($this->base64url('rvte8A+pXfpNXkspbZ/jlA=='), $results['tag']);
    }

    function testA192Encrypt() {
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $plaintext = base64_decode('AAAAAAAAAAAAAAAA');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('mOckfAfw/kEcJn5D'), $results['ciphertext']);
        $this->assertEquals($this->base64url('c9Bq0j0izBalxOLcV+DeVg=='), $results['tag']);
    }

    function testA256Encrypt() {
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        $plaintext = base64_decode('AAAAAAAAAAAAAAAA');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('zqdAPU1ga24HTsXT'), $results['ciphertext']);
        $this->assertEquals($this->base64url('7CJ9yq1uw1LubP0UBQuVkw=='), $results['tag']);
    }
}
?>
