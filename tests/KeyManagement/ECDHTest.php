<?php

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

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

    protected function getECDHStub() {
        // From Appendix C of RFC 7518
        $ephemeral_key = new ECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps'
        ], 'php');

        $stub = $this->getMockBuilder('SimpleJWT\Crypt\KeyManagement\ECDH')
            ->setMethods(['createEphemeralKey'])->setConstructorArgs(['ECDH-ES'])->getMock();

        $stub->method('createEphemeralKey')->willReturn($ephemeral_key);

        return $stub;
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

    public function testProduceECDH() {
        if (!$this->isAlgAvailable()) return;

        $ecdh = $this->getECDHStub();
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

        $ecdh = $this->getECDHStub();
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
