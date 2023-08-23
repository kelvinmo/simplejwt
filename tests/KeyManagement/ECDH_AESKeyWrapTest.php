<?php

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class ECDH_AESKeyWrapTest extends TestCase {
    protected function isAlgAvailable($alg) {
        $ecdh = new ECDH_AESKeyWrap(null);
        if (count($ecdh->getSupportedAlgs()) == 0) {
            $this->markTestSkipped('Alg not available: ' . $alg);
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

    protected function getSymmetricKeySet($agreed_key) {
        return \SimpleJWT\Keys\KeySet::createFromSecret($agreed_key, 'bin');
    }

    function testECDHES_A128KW() {
        if (!$this->isAlgAvailable('ECDH-ES+A128KW')) return;

        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new ECDH_AESKeyWrap('ECDH-ES+A128KW');
        $public_set = $this->getPublicKeySet();
        $private_set = $this->getPrivateKeySet();
        $headers = [
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];

        $derived_key_from_public = $alg->deriveKey($public_set, $headers);
        $derived_key_set_from_public = $this->getSymmetricKeySet($derived_key_from_public);
        $encrypted_key = $alg->encryptKey($key, $derived_key_set_from_public, $headers);

        $derived_key_from_private = $alg->deriveKey($private_set, $headers);
        $derived_key_set_from_private = $this->getSymmetricKeySet($derived_key_from_private);
        $decrypted_key = $alg->decryptKey($encrypted_key, $derived_key_set_from_private, $headers);
        
        $this->assertEquals($key, $decrypted_key);
    }

    function testECDHES_A192KW() {
        if (!$this->isAlgAvailable('ECDH-ES+A192KW')) return;

        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new ECDH_AESKeyWrap('ECDH-ES+A192KW');
        $public_set = $this->getPublicKeySet();
        $private_set = $this->getPrivateKeySet();
        $headers = [
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];


        $derived_key_from_public = $alg->deriveKey($public_set, $headers);
        $derived_key_set_from_public = $this->getSymmetricKeySet($derived_key_from_public);
        $encrypted_key = $alg->encryptKey($key, $derived_key_set_from_public, $headers);

        $derived_key_from_private = $alg->deriveKey($private_set, $headers);
        $derived_key_set_from_private = $this->getSymmetricKeySet($derived_key_from_private);
        $decrypted_key = $alg->decryptKey($encrypted_key, $derived_key_set_from_private, $headers);
        
        $this->assertEquals($key, $decrypted_key);
    }

    function testECDHES_A256KW() {
        if (!$this->isAlgAvailable('ECDH-ES+A256KW')) return;

        $key = pack('H*', '00112233445566778899AABBCCDDEEFF');

        $alg = new ECDH_AESKeyWrap('ECDH-ES+A256KW');
        $public_set = $this->getPublicKeySet();
        $private_set = $this->getPrivateKeySet();
        $headers = [
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];

        $derived_key_from_public = $alg->deriveKey($public_set, $headers);
        $derived_key_set_from_public = $this->getSymmetricKeySet($derived_key_from_public);
        $encrypted_key = $alg->encryptKey($key, $derived_key_set_from_public, $headers);

        $derived_key_from_private = $alg->deriveKey($private_set, $headers);
        $derived_key_set_from_private = $this->getSymmetricKeySet($derived_key_from_private);
        $decrypted_key = $alg->decryptKey($encrypted_key, $derived_key_set_from_private, $headers);
        
        $this->assertEquals($key, $decrypted_key);
    }
}

?>
