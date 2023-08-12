<?php

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\ECDHKeyInterface;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class ECKeyMock extends ECKey {
    public function createEphemeralKey(string $crv): ECDHKeyInterface {
        // From Appendix C of RFC 7518
        return new ECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps'
        ], 'php');
    }

    public function getPublicKey() {
        return new ECKeyMock([
            'kid' => $this->data['kid'],
            'kty' => $this->data['kty'],
            'crv' => $this->data['crv'],
            'x' => $this->data['x'],
            'y' => $this->data['y']
        ], 'php');
    }
}

class ECDHTest extends TestCase {
    protected function isAlgAvailable() {
        $ecdh = new ECDH(null);
        if (!in_array('ECDH-ES', $ecdh->getSupportedAlgs())) {
            $this->markTestSkipped('Alg not available: ECDH-ES');
            return false;
        } else {
            return true;
        }
    }

    protected function getPrivateKeySet() {
        $set = new KeySet();

        $set->add(new ECKeyMock([
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

    public function testProduceECDH() {
        if (!$this->isAlgAvailable()) return;

        $ecdh = new ECDH('ECDH-ES');
        $keys = $this->getPublicKeySet();
        $headers = [
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i'
        ];

        $result = $ecdh->deriveKey($keys, $headers);

        $this->assertArrayHasKey('epk', $headers);
        $this->assertEquals('gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0', $headers['epk']['x']);
        $this->assertArrayNotHasKey('d', $headers['epk']);

        $this->assertEquals('VqqN6vgjbSBcIijNcacQGg', Util::base64url_encode($result));
    }

    public function testConsumeECDH() {
        if (!$this->isAlgAvailable()) return;

        $ecdh = new ECDH('ECDH-ES');
        $keys = $this->getPrivateKeySet();
        $headers = [
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
            'epk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps'
            ]
        ];

        $result = $ecdh->deriveKey($keys, $headers);
        $this->assertEquals('VqqN6vgjbSBcIijNcacQGg', Util::base64url_encode($result));
    }

}

?>
