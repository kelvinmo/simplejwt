<?php

use SimpleJWT\Keys\RSAKey;
use SimpleJWT\Keys\ECKey;

class KeyTest extends \PHPUnit_Framework_TestCase {
    public function testRSA() {
        $pem = file_get_contents('rsa_private.pem');
        $key = new RSAKey($pem, 'pem');
        $this->assertFalse($key->isPublic());
        $this->assertEquals($pem, $key->toPEM());

        $pem = file_get_contents('rsa_public.pem');
        $key = new RSAKey($pem, 'pem');
        $this->assertTrue($key->isPublic());
        $this->assertEquals($pem, $key->toPEM());
    }


    public function testEC() {
        $pem = file_get_contents('ec_private.pem');
        $key = new ECKey($pem, 'pem');
        $this->assertFalse($key->isPublic());
        $this->assertEquals($pem, $key->toPEM());

        $pem = file_get_contents('ec_public.pem');
        $key = new ECKey($pem, 'pem');
        $this->assertTrue($key->isPublic());
        //$this->assertEquals($pem, $key->toPEM()); // Different OIDs
    }
}
?>
