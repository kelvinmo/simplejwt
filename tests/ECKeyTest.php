<?php

use SimpleJWT\Keys\ECKey;
use PHPUnit\Framework\TestCase;

class ECKeyTest extends TestCase {
    /**
     * Test whether an EC key that is not on the same curve as a specified
     * key is accepted.  This mitigates against invalid curve attacks.
     * 
     * @see https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/
     */
    public function testInvalidCurve() {
        $private = new ECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'=> 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'=> 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'=> 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw'
        ], 'php');
        
        $malicious_public = new ECKey([
            'kty' => 'EC',
            'x' => 'gTli65eTQ7z-Bh147ff8K3m7k2UiDiG2LpYkWAaFJCc',
            'y' => 'cLAnjKa4bzjD7DJVPwa9EPrRzMG7rONgsiUD-kf30Fs',
            'crv' => 'P-256'
        ], 'php');

        $this->assertEquals(false, $private->isOnSameCurve($malicious_public));
    }
}

?>