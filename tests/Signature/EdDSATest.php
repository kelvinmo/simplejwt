<?php

namespace SimpleJWT\Crypt\Signature;

use SimpleJWT\Util\Util;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\OKPKey;
use PHPUnit\Framework\TestCase;

class EdDSATest extends TestCase {
    function testEdDSA_test2() {
        // https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        $data = hex2bin('72');

        $private_set = new KeySet();
        $private_set->add(new OKPKey([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'kid' => 'test2',
            'd' => Util::base64url_encode(hex2bin('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')),
            'x' => Util::base64url_encode(hex2bin('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'))
        ], 'php'));

        $public_set = new KeySet();
        $public_set->add($private_set->getById('test2')->getPublicKey());

        $signer = new EdDSA('EdDSA');
        $signature = $signer->sign($data, $private_set);

        $this->assertEquals(Util::base64url_encode(hex2bin('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')), $signature);
        $this->assertTrue($signer->verify($signature, $data, $public_set));
    }
}

?>