<?php

namespace SimpleJWT\Crypt\KeyManagement;

use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\OKPKey;
use SimpleJWT\Keys\KeyInterface;
use SimpleJWT\Keys\ECDHKeyInterface;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class ECKeyMock extends ECKey {
    public function createEphemeralKey(): ECDHKeyInterface {
        // From Appendix C of RFC 7518
        return new ECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps'
        ], 'php');
    }

    public function getPublicKey(): ?KeyInterface {
        return new ECKeyMock([
            'kty' => $this->data['kty'],
            'crv' => $this->data['crv'],
            'x' => $this->data['x'],
            'y' => $this->data['y']
        ], 'php');
    }
}

class ECDHTest extends TestCase {
    protected function isECAlgAvailable() {
        $ecdh = new ECDH(null);
        if (!in_array('ECDH-ES', $ecdh->getSupportedAlgs())) {
            $this->markTestSkipped('Alg not available: ECDH-ES');
            return false;
        } else {
            return true;
        }
    }

    protected function isX25519AlgAvailable() {
        if (!$this->isECAlgAvailable()) return false;
        if (!function_exists('sodium_crypto_scalarmult')) {
            $this->markTestSkipped('Alg not available: X25519');
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
        if (!$this->isECAlgAvailable()) return;

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
        if (!$this->isECAlgAvailable()) return;

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

    public function testX25519() {
        if (!$this->isX25519AlgAvailable()) return;

        // Vectors are from Appendix A.6 of RFC 8037
        $public_key = new OKPKey([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x' => '3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08'
        ], 'php');

        $ephemeral_key = new OKPKey([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'd' => 'dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo',
            'x' => 'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo'
        ], 'php');

        $Z = $ephemeral_key->deriveAgreementKey($public_key);
        $this->assertEquals('Sl2dW6TOLeFyjjv0gDUPJeB-IclH0Z4zdvCbPB4WF0I', Util::base64url_encode($Z));
    }
}

?>
