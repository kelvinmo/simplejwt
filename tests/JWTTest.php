<?php

namespace SimpleJWT;

use PHPUnit\Framework\TestCase;

// Override time() in current namespace for testing
function time() {
    return 1300000000;
}

class JWTTest extends TestCase {

    protected function getJWTClaims() {
        return [
            "iss" => "joe",
            "exp" => 1300819380,
            "http://example.com/is_root" => true
        ];
    }

    protected function getPrivateKeySet() {
        $set = new Keys\KeySet();

        $set->add(new Keys\SymmetricKey([
            "kty" => "oct",
            "k" => "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
            "kid" => "hmac"
        ], 'php'));

        $set->add(new Keys\RSAKey([
            "kty" => "RSA",
            "n" => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e" => "AQAB",
            "d" => "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
            "p" => "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
            "q" => "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
            "dp" => "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
            "dq" => "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
            "qi" => "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
            "kid" => "RSA"
        ], 'php'));

        $set->add(new Keys\ECKey([
            "kty" => "EC",
            "crv" => "P-256",
            "x" => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y" => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d" => "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
            "kid" => "EC"
        ], 'php'));

        $set->add(new Keys\ECKey([
            "kty" => "EC",
            "crv" => "secp256k1",
            "x" => "QGVPYUfFqCwBeaapsTbrtQZFU5h0EXBO8iEzH3pUz-c",
            "y" => "3BZVYSHcdZMkWtnnenhAiCXdWJyVGEMKMECIdzVD11U",
            "d" => "jA_zoAn0BhF0M7x8A3zZtWuFXI9U-A1jAGXjTKHsMkY",
            "kid" => "secp256k1"
        ], 'php'));

        return $set;
    }

    protected function getPublicKeySet() {
        $private = $this->getPrivateKeySet();
        $set = new Keys\KeySet();

        foreach ($private->getKeys() as $key) {
            if ($key instanceof Keys\SymmetricKey) {
                $set->add($key);
            } else {
                $set->add($key->getPublicKey());
            }
        }

        return $set;
    }

    function testGenerateHMAC() {
        $set = $this->getPrivateKeySet();
        $claims = $this->getJWTClaims();
        $jwt = new JWT(['typ' => 'JWT', 'alg' => 'HS256'], $claims);
        $token = $jwt->encode($set, null, false);
        $this->assertEquals('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6XC9cL2V4YW1wbGUuY29tXC9pc19yb290Ijp0cnVlfQ.0stp4GfJhgUSjqUtkZ1Hfmt1bvPKiHSzojeTw3sr7R8', $token);
    }

    function testGenerateRSA() {
        $set = $this->getPrivateKeySet();
        $claims = $this->getJWTClaims();
        $jwt = new JWT(['alg' => 'RS256'], $claims);
        $token = $jwt->encode($set, null, false);
        $this->assertEquals('eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6XC9cL2V4YW1wbGUuY29tXC9pc19yb290Ijp0cnVlfQ.WLAkxL55suP-DBGVRHnJk-gT3-U_lVwUeINTxPx42MnneO4Q8Hv1A4331-BLHzSB3bRvoGtHv-IdMykYqGPi8PkdXGuBqJIkL9_HNb2YHtS_ALL2xYSUdHntxPcMr_2HHmVsePhYESlLpfW4wR2CKHXn13gQCjbZTXFwGyvuj_BH5ozpK0JdlttGQ7EL3Uetjv2143F-lI5w_Ttw4Ob4M8jsu7-K63MvqZvWexq3oBzmH4soLTSu84I63ZoyS7mxYvMxvCgV5Is8TGsY81pmyXMeMGb1GodaLrULnc5alz96fDekZYFT8mfuRVZP6Kmsu6MqsszPILY4YuWq6bSkXg', $token);
    }

    function testGenerateEC() {
        $set = $this->getPrivateKeySet();
        $claims = $this->getJWTClaims();
        $jwt = new JWT(['alg' => 'ES256'], $claims);
        $token = $jwt->encode($set, 'EC', false);

        // Note that ECDSA generates a different signature every time, as a random
        // number is used as part of the algorithm.
        $set2 = $this->getPublicKeySet();
        $jwt2 = JWT::decode($token, $set2, 'ES256', 'EC');
        $this->assertTrue($jwt2->getClaim('http://example.com/is_root'));
    }

    function testGenerateEC_secp256k1() {
        $algs = Crypt\AlgorithmFactory::getSupportedAlgs('sig');
        if (!in_array('ES256K', $algs)) {
            $this->markTestSkipped('ES256K algorithm not available');
            return;
        }

        $set = $this->getPrivateKeySet();
        $claims = $this->getJWTClaims();
        $jwt = new JWT(['alg' => 'ES256K'], $claims);
        $token = $jwt->encode($set, 'secp256k1', false);

        // Note that ECDSA generates a different signature every time, as a random
        // number is used as part of the algorithm.
        $set2 = $this->getPublicKeySet();
        $jwt2 = JWT::decode($token, $set2, 'ES256K', 'secp256k1');
        $this->assertTrue($jwt2->getClaim('http://example.com/is_root'));
    }

    function testDeserialiseCompact() {
        $token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $result = JWT::deserialise($token);

        $this->assertEquals('HS256', $result['signatures'][0]['headers']['alg']);
        $this->assertTrue($result['claims']['http://example.com/is_root']);
        $this->assertEquals('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ', $result['signatures'][0]['signing_input']);
        $this->assertEquals('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', $result['signatures'][0]['signature']);
    }

    function testDeserialiseJSON() {
        $token = '{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","signatures":[{"protected":"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9","signature":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}]}';
        $result = JWT::deserialise($token, JWT::JSON_FORMAT);

        $this->assertEquals('HS256', $result['signatures'][0]['headers']['alg']);
        $this->assertTrue($result['claims']['http://example.com/is_root']);
        $this->assertEquals('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ', $result['signatures'][0]['signing_input']);
        $this->assertEquals('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', $result['signatures'][0]['signature']);
    }

    function testVerifyHMAC() {
        $set = $this->getPublicKeySet();
        $token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $jwt = JWT::decode($token, $set, 'HS256');
        $this->assertTrue($jwt->getClaim('http://example.com/is_root'));
    }

    function testVerifyRSA() {
        $set = $this->getPublicKeySet();
        $token = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw';
        $jwt = JWT::decode($token, $set, 'RS256');
        $this->assertTrue($jwt->getClaim('http://example.com/is_root'));
    }

    function testVerifyEC() {
        $set = $this->getPublicKeySet();
        $token = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
        $jwt = JWT::decode($token, $set, 'ES256', 'EC');
        $this->assertTrue($jwt->getClaim('http://example.com/is_root'));
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    function testAlgFailure() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
        }

        $set = $this->getPublicKeySet();
        $token = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
        $jwt = JWT::decode($token, $set, 'RS256'); // Error - should be ES256
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    function testSignatureFailure() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
        }
        
        $set = $this->getPublicKeySet();
        $token = 'eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6XC9cL2V4YW1wbGUuY29tXC9pc19yb290Ijp0cnVlfQ.NrP7T3zsezqVjBPI35nJBtIQeoOrsT7Rib5NdaOzpgM';
        $jwt = JWT::decode($token, $set, 'HS256');
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    function testTimeFailure() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
        }
        
        $set = $this->getPrivateKeySet();
        $claims = $this->getJWTClaims();
        $claims['exp'] = 1;
        $jwt = new JWT(['typ' => 'JWT', 'alg' => 'HS256'], $claims);
        $token = $jwt->encode($set, null, false);

        $set2 = $this->getPublicKeySet();
        $jwt2 = JWT::decode($token, $set2, 'HS256');
    }
}
?>
