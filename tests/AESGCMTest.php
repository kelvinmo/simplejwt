<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;

class AESGCMTest extends \PHPUnit_Framework_TestCase {
    protected function isAlgAvailable($alg) {
        $aesgcm = new AESGCM(null);
        if (!in_array($alg, $aesgcm->getSupportedAlgs())) {
            $this->markTestSkipped('Alg not available: ' . $alg);
            return false;
        } else {
            return true;
        }
    }

    protected function base64url($base64) {
        return Util::base64url_encode(base64_decode($base64));
    }

    function testA128GCMEncrypt() {
        if (!$this->isAlgAvailable('A128GCM')) return;

        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAA==');
        $plaintext = base64_decode('AAAAAAAAAAAAAAAA');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('A4jazmC2o5LzKMK5'), $results['ciphertext']);
        $this->assertEquals($this->base64url('rvte8A+pXfpNXkspbZ/jlA=='), $results['tag']);
    }

    function testA128GCMDecrypt() {
        if (!$this->isAlgAvailable('A128GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAA==');
        $ciphertext = base64_decode('A4jazmC2o5LzKMK5');
        $tag = $this->base64url('rvte8A+pXfpNXkspbZ/jlA==');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

        $this->assertEquals(base64_decode('AAAAAAAAAAAAAAAA'), $results);
    }

    function testA128GCMIncorrectTag() {
        if (!$this->isAlgAvailable('A128GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAA==');
        $ciphertext = base64_decode('A4jazmC2o5LzKMK5');
        $tag = $this->base64url('AAAAAAAAAAAAAAAAAAAAAA==');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A128GCM');
        $this->setExpectedException('SimpleJWT\\Crypt\\CryptException');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);
    }

    function testA192Encrypt() {
        if (!$this->isAlgAvailable('A192GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $plaintext = base64_decode('AAAAAAAAAAAAAAAA');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('mOckfAfw/kEcJn5D'), $results['ciphertext']);
        $this->assertEquals($this->base64url('c9Bq0j0izBalxOLcV+DeVg=='), $results['tag']);
    }

    function testA192Decrypt() {
        if (!$this->isAlgAvailable('A192GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $ciphertext = base64_decode('mOckfAfw/kEcJn5D');
        $tag = $this->base64url('c9Bq0j0izBalxOLcV+DeVg==');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

        $this->assertEquals(base64_decode('AAAAAAAAAAAAAAAA'), $results);
    }

    function testA192GCMIncorrectTag() {
        if (!$this->isAlgAvailable('A192GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $ciphertext = base64_decode('mOckfAfw/kEcJn5D');
        $tag = $this->base64url('AAAAAAAAAAAAAAAAAAAAAA==');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A192GCM');
        $this->setExpectedException('SimpleJWT\\Crypt\\CryptException');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);
    }

    function testA256Encrypt() {
        if (!$this->isAlgAvailable('A256GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        $plaintext = base64_decode('AAAAAAAAAAAAAAAA');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('zqdAPU1ga24HTsXT'), $results['ciphertext']);
        $this->assertEquals($this->base64url('7CJ9yq1uw1LubP0UBQuVkw=='), $results['tag']);
    }

    function testA256Decrypt() {
        if (!$this->isAlgAvailable('A256GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        $ciphertext = base64_decode('zqdAPU1ga24HTsXT');
        $tag = $this->base64url('7CJ9yq1uw1LubP0UBQuVkw==');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);

        $this->assertEquals(base64_decode('AAAAAAAAAAAAAAAA'), $results);
    }

    function testA256GCMIncorrectTag() {
        if (!$this->isAlgAvailable('A256GCM')) return;
        
        $cek = base64_decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        $ciphertext = base64_decode('zqdAPU1ga24HTsXT');
        $tag = $this->base64url('AAAAAAAAAAAAAAAAAAAAAA==');
        $iv = $this->base64url('AAAAAAAAAAAAAAAA');
        $additional = '';

        $alg = new AESGCM('A256GCM');
        $this->setExpectedException('SimpleJWT\\Crypt\\CryptException');
        $results = $alg->decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv);
    }
}
?>
