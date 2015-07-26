<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;

class PBES2Test extends \PHPUnit_Framework_TestCase {

    protected function getKeySet($password) {
        return \SimpleJWT\Keys\KeySet::createFromSecret($password, 'bin');
    }

    function testPBES2() {
        //$header = '{"alg":"PBES2-HS256+A128KW","p2s":"2WCTcJZ1Rvd_CJuJripQ1w","p2c":4096,"enc":"A128CBC-HS256","cty":"jwk+json"}';
        //$plaintext = '{"kty":"RSA","kid":"juliet@capulet.lit","use":"enc","n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q","e":"AQAB","d":"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ","p":"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws","q":"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s","dp":"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c","dq":"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots","qi":"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"}';
        $cek = Util::base64url_decode('bxsZNEIdFE5csDjwQdBScKGDJDfK7LmsgReZwsMw_bY');

        $password = 'Thus from my lips, by yours, my sin is purged.';
        $keys = $this->getKeySet($password);

        $stub = $this->getMockBuilder('SimpleJWT\Crypt\PBES2')
            ->setMethods(array('generateSaltInput'))->setConstructorArgs(array('PBES2-HS256+A128KW'))->getMock();

        $stub->method('generateSaltInput')->willReturn(Util::base64url_decode('2WCTcJZ1Rvd_CJuJripQ1w'));
        $stub->setIterations(4096);

        $headers = array('alg' => 'PBES2-HS256+A128KW');

        $encrypted_key = $stub->encryptKey($cek, $keys, $headers);

        $this->assertEquals(4096, $headers['p2c']);
        $this->assertEquals('2WCTcJZ1Rvd_CJuJripQ1w', $headers['p2s']);
        $this->assertEquals('TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA', $encrypted_key);
    }
}

?>
