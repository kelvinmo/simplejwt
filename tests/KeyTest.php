<?php

use SimpleJWT\JWE;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Keys\OKPKey;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase {
    protected $symmetric_key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

    function testSymmetricCreate() {
        $key = new SymmetricKey($this->symmetric_key, 'base64url');
        $key_data = $key->getKeyData();
        $this->assertEquals($this->symmetric_key, $key_data['k']);
    }

    function testSymmetricBase64Create() {
        $base64_key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ+EstJQLr/T+1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

        $key = new SymmetricKey($base64_key, 'base64');
        $key_data = $key->getKeyData();
        $this->assertEquals($this->symmetric_key, $key_data['k']);
    }

    function testSymmetricJSONCreate() {
        $json = json_encode(['kty' => 'oct', 'k' => $this->symmetric_key]);

        $key = new SymmetricKey($json, 'json');
        $key_data = $key->getKeyData();
        $this->assertEquals($this->symmetric_key, $key_data['k']);
    }

    function testSymmetricCBORDecode() {
        $base64url_key = 'zwsUMfNVd18EOMKUl2lmf4j3A1zpqJhDhpnJWPey76g';
        $cbor = 'ogEEIFggzwsUMfNVd18EOMKUl2lmf4j3A1zpqJhDhpnJWPey76g=';

        $key = new SymmetricKey(base64_decode($cbor), 'cbor');
        $key_data = $key->getKeyData();
        $this->assertEquals($base64url_key, $key_data['k']);
    }

    function testOKPCBORDecode() {
        $base64url_d = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
        $cbor = 'pAEBAycgBiNYIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f';

        $key = new OKPKey(base64_decode($cbor), 'cbor');
        $key_data = $key->getKeyData();
        $this->assertEquals('Ed25519', $key_data['crv']);
        $this->assertEquals($base64url_d, $key_data['d']);
    }

    function testPassword() {
        $password = 'test_password';

        $key = new SymmetricKey($this->symmetric_key, 'base64url');
        $key_data = $key->getKeyData();
        $jwk = $key->toJWK($password);

        $loaded_key = new SymmetricKey($jwk, 'jwe', $password);
        $loaded_key_data = $loaded_key->getKeyData();
        $this->assertEquals($key_data['k'], $loaded_key_data['k']);
    }

    function testPasswordJSON() {
        $password = 'test_password';

        $key = new SymmetricKey($this->symmetric_key, 'base64url');
        $key_data = $key->getKeyData();
        $jwk = $key->toJWK($password, JWE::JSON_FORMAT);

        $loaded_key = new SymmetricKey($jwk, 'json', $password);
        $loaded_key_data = $loaded_key->getKeyData();
        $this->assertEquals($key_data['k'], $loaded_key_data['k']);
    }
}
?>
