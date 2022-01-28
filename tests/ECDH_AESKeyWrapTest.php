<?php

use SimpleJWT\Crypt\ECDH_AESKeyWrap;
use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class ECDH_AESKeyWrapTest extends TestCase {
    protected function isAlgAvailable() {
        $ecdh = new ECDH_AESKeyWrap(null);
        if (count($ecdh->getSupportedAlgs()) == 0) {
            $this->markTestSkipped('Alg not available: ECDH-ES+AxxxKW');
            return false;
        } else {
            return true;
        }
    }

    protected function getPrivateKeySet() {
        $set = new KeySet();

        $set->add(new ECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck'
        ], 'php'));

        return $set;
    }

    private function getPublicKeySet() {
        $private = $this->getPrivateKeySet();
        $set = new KeySet();

        foreach ($private->getKeys() as $key) {
            $set->add($key->getPublicKey());
        }

        return $set;
    }

    function testECDHES_A128KW() {
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new ECDH_AESKeyWrap('ECDH-ES+A128KW');
        $public_set = $this->getPublicKeySet();
        $private_set = $this->getPrivateKeySet();
        $headers = [
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];

        $encrypted_key = $alg->encryptKey($key, $public_set, $headers);
        $decrypted_key = $alg->decryptKey($encrypted_key, $private_set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testECDHES_A192KW() {
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new ECDH_AESKeyWrap('ECDH-ES+A192KW');
        $public_set = $this->getPublicKeySet();
        $private_set = $this->getPrivateKeySet();
        $headers = [
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];


        $encrypted_key = $alg->encryptKey($key, $public_set, $headers);
        $decrypted_key = $alg->decryptKey($encrypted_key, $private_set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }

    function testECDHES_A256KW() {
        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new ECDH_AESKeyWrap('ECDH-ES+A256KW');
        $public_set = $this->getPublicKeySet();
        $private_set = $this->getPrivateKeySet();
        $headers = [
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];

        $encrypted_key = $alg->encryptKey($key, $public_set, $headers);
        $decrypted_key = $alg->decryptKey($encrypted_key, $private_set, $headers);
        $this->assertEquals($key, $decrypted_key);
    }
}

?>
