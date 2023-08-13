<?php

namespace SimpleJWT;

use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\ECKey;
use SimpleJWT\Keys\RSAKey;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;


class JWETest extends TestCase {
    protected $multi_token = '{
      "protected":
       "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":
       {"jku":"https://server.example.com/keys.jwks"},
      "recipients":[
       {"header":
         {"alg":"RSA1_5","kid":"2011-04-29"},
        "encrypted_key":
         "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
       {"header":
         {"alg":"A128KW","kid":"7"},
        "encrypted_key":
         "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
      "iv": "AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
     }';


    protected function getPrivateKeySet() {
        $set = new KeySet();

        $set->add(new RSAKey([
            "kty" => "RSA",
            "kid" => "2011-04-29",
            "n" => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e" => "AQAB",
            "d" => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            "p" => "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            "q" => "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            "dp" => "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            "dq" => "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            "qi" => "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
        ], 'php'));

        $set->add(new ECKey([
            "kty"=> "EC",
            "kid" => "issue-159",
            "crv" => "P-384",
            "use" => "enc",
            "d" => "3DCgwJeF_IRdhF1B8JYRZOm4Frt_XrknFotgE_RcVj_z053yhHF4zhM6W-z7dd2X",
            "x" => "q4yHCxdvXDA6PODaM9IkpjCUh9gRgpkIN_gV1i5HzJUOHCkC4HMrFiIduZZsVdQf",
            "y" => "fFrsS5ZIlf0CKAnxRXhnbSHcGTByVxULEPyN_9jKOlb85wZv4VoIEtIBxeHYkLCe"
        ], 'php'));

        $set->add(new SymmetricKey([
            "kty" => "oct",
            "kid" => "7",
            "k" => "GawgguFyGrWKav7AX4VKUg"
        ], 'php'));

        return $set;
    }

    protected function getPublicKeySet() {
        $private = $this->getPrivateKeySet();
        $set = new KeySet();

        foreach ($private->getKeys() as $key) {
            if ($key instanceof SymmetricKey) {
                $set->add($key);
            } else {
                $set->add($key->getPublicKey());
            }
        }

        return $set;
    }

    protected function getDirectKeySet() {
        $set = new KeySet();
        $set->add(new SymmetricKey([
            "kty" => "oct",
            "k" => "lhMUu-TevIFn6mFgPzRgUyZVlIuHeu4uAzn6dexz7vY"
        ], 'php'));
        return $set;
    }

    public function testEncryptRSA() {
        // From Appendix A.2 of RFC 7516
        $plaintext = 'Live long and prosper.';
        $public_set = $this->getPublicKeySet();

        $builder = $this->getMockBuilder('SimpleJWT\JWE');
        if (method_exists($builder, 'setMethods')) {
            $stub = $builder->setConstructorArgs([["alg" => "RSA1_5","enc" => "A128CBC-HS256"], $plaintext])
            ->setMethods(['generateCEK'])
            ->setMethods(['generateIV'])
            ->getMock();
        } else {
            $stub = $builder->setConstructorArgs([["alg" => "RSA1_5","enc" => "A128CBC-HS256"], $plaintext])
            ->onlyMethods(['generateCEK', 'generateIV'])
            ->getMock();
        }
        $stub->method('generateCEK')->willReturn(base64_decode('BNMfxVSd/P4LZJ36P6pqzmt81C1vawnbyLEA8I+cLM8='));
        $stub->method('generateIV')->willReturn('AxY8DCtDaGlsbGljb3RoZQ');

        // We cannot directly compare the compact JWE format result, as the RSA1_5 padding
        // involves a random string generated by OpenSSL. Therefore we generate the JWE in
        // JSON format and compare each component other than the encrypted key.
        $token_json = json_decode($stub->encrypt($public_set, null, JWE::JSON_FORMAT), true);
        $this->assertEquals('eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', $token_json['protected']);
        $this->assertEquals('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', $token_json['ciphertext']);
        $this->assertEquals('AxY8DCtDaGlsbGljb3RoZQ', $token_json['iv']);
        $this->assertEquals('9hH0vgRfYgPnAHOd8stkvw', $token_json['tag']);
    }

    public function testDecryptRSA() {
        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'RSA1_5');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testEncryptAESKW() {
        // From Appendix A.3 of RFC 7516
        $plaintext = 'Live long and prosper.';
        $public_set = $this->getPublicKeySet();

        $builder = $this->getMockBuilder('SimpleJWT\JWE');
        if (method_exists($builder, 'setMethods')) {
            $stub = $builder->setConstructorArgs([["alg" => "A128KW","enc" => "A128CBC-HS256"], $plaintext])
            ->setMethods(['generateCEK'])
            ->setMethods(['generateIV'])
            ->getMock();
        } else {
            $stub = $builder->setConstructorArgs([["alg" => "A128KW","enc" => "A128CBC-HS256"], $plaintext])
            ->onlyMethods(['generateCEK', 'generateIV'])
            ->getMock();
        }
        $stub->method('generateCEK')->willReturn(base64_decode('BNMfxVSd/P4LZJ36P6pqzmt81C1vawnbyLEA8I+cLM8='));
        $stub->method('generateIV')->willReturn('AxY8DCtDaGlsbGljb3RoZQ');

        $token = $stub->encrypt($public_set);
        $this->assertEquals('eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ', $token);

        $token_json = json_decode($stub->encrypt($public_set, null, JWE::JSON_FORMAT), true);
        $this->assertEquals('eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', $token_json['protected']);
        $this->assertEquals('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ', $token_json['encrypted_key']);
        $this->assertEquals('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', $token_json['ciphertext']);
        $this->assertEquals('AxY8DCtDaGlsbGljb3RoZQ', $token_json['iv']);
        $this->assertEquals('U0m_YmjN04DJvceFICbCVQ', $token_json['tag']);
    }

    public function testDecryptAESKW() {
        // From Appendix A.3 of RFC 7516
        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testDecryptJSONFlat() {
        $plaintext = 'Live long and prosper.';

        $token = '{"protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"U0m_YmjN04DJvceFICbCVQ"}';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testDecryptMulti() {
        $plaintext = 'Live long and prosper.';

        $key = $this->getPrivateKeySet()->getById('7');
        $private_set = new KeySet();
        $private_set->add($key);

        $test_jwe = JWE::decrypt($this->multi_token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testEncryptDirect() {
        $plaintext = 'Live long and prosper.';
        $public_set = $this->getDirectKeySet();

        $builder = $this->getMockBuilder('SimpleJWT\JWE');
        if (method_exists($builder, 'setMethods')) {
            $stub = $builder->setConstructorArgs([["alg" => "dir", "enc" => "A128CBC-HS256", "kid" => "YI3EoIK"], $plaintext])
            ->setMethods(['generateIV'])
            ->getMock();
        } else {
            $stub = $builder->setConstructorArgs([["alg" => "dir", "enc" => "A128CBC-HS256", "kid" => "YI3EoIK"], $plaintext])
            ->onlyMethods(['generateIV'])
            ->getMock();
        }

        $stub->method('generateIV')->willReturn('h7LOWyYIlzq4BJV5V1vxhg');
        
        $token = $stub->encrypt($public_set);
        $this->assertEquals('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiWUkzRW9JSyJ9..h7LOWyYIlzq4BJV5V1vxhg.aZEMslyY-kybAWlb8hM6aWCocQ3TMghMhNwk4Meyjb4.IDEVZS1i76IHNSd5sAt7tA', $token);

        $token_json = json_decode($stub->encrypt($public_set, null, JWE::JSON_FORMAT), true);
        $this->assertEquals('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiWUkzRW9JSyJ9', $token_json['protected']);
        $this->assertEquals('aZEMslyY-kybAWlb8hM6aWCocQ3TMghMhNwk4Meyjb4', $token_json['ciphertext']);
        $this->assertEquals('h7LOWyYIlzq4BJV5V1vxhg', $token_json['iv']);
        $this->assertEquals('IDEVZS1i76IHNSd5sAt7tA', $token_json['tag']);
    }

    public function testDecryptDirect() {
        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiWUkzRW9JSyJ9..h7LOWyYIlzq4BJV5V1vxhg.aZEMslyY-kybAWlb8hM6aWCocQ3TMghMhNwk4Meyjb4.IDEVZS1i76IHNSd5sAt7tA';
        $private_set = $this->getDirectKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'dir');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testDecryptDirectJSON() {
        $plaintext = 'Live long and prosper.';

        $token = '{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiWUkzRW9JSyJ9","iv":"h7LOWyYIlzq4BJV5V1vxhg","ciphertext":"aZEMslyY-kybAWlb8hM6aWCocQ3TMghMhNwk4Meyjb4","tag":"IDEVZS1i76IHNSd5sAt7tA"}';
        $private_set = $this->getDirectKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'dir');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }


    public function testDecryptECDHAESKW() {
        // https://github.com/kelvinmo/simplejwt/issues/159
        $algs = Crypt\AlgorithmFactory::getSupportedAlgs('key');
        if (!in_array('ECDH-ES+A256KW', $algs)) {
            $this->markTestSkipped('ECDH-ES+A256KW algorithm not available');
            return;
        }

        $token = 'eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiVDFIazlQell6SUY5NW9ESDJENTFZXzJGVUZuZ3RKZWxpbW11UTZJbHlyVWhuVGlfYlk1ZFplY0lPNExQRmp1byIsInkiOiJlLVBQbTNEQjB0N2F1RUNCV0Q0MkZxMlVDeXNuQ0NjQUxDUy1NWHMwclV3U0pLQmFMWTcwb1lzcWprMnJQVjROIiwiY3J2IjoiUC0zODQifX0.6vW-S_7om9iHMYc2JzkwijQV4msn55YRrDYQ2EMs3-bg3Y7I0dBrDA.CQ45omsfTgrZlrJd.58LMMeqXOogn6i6JI5VbrFucwI_hStOGNXgOqXsExNARXlYPSHweSXXGS_nYaa90srl9a5HTbn1YJEtduB0YKekULRXK1la5uOiHnw5tuRJUqXVTA-_l_Nv7PZWzPZOua2quUGMw5c8y55c8qImO02gw_tbopnqwROUHR-eeBMiRwEkpBDl8AlSOQsLd-6MZ3kqaLuGyhw0rQ9DPZlucB1DB0rF2WYEwnz72I1aB2XLmrVuIRkTbVRRxMp9Qt8BLP8Uay-8Qr3HvMfQDftKydtAKiQLXHTMLoo5H8s69i-1baFynJjH4nNpnujJGONkBSQg9RmWf-5CdiZnQC1g4hSvL5p6RM0sGXR4jORlzd-TNSmZeOe1mvEHifCmeyCQ1T0NNBrtsSUeT6lckEFjyvjKau6eZxoa3nyzpzMooNw8u-e-s9uctYmdVmYm75PWqkzencTnccTtmZjuBdehplM0SLbGYrxoxIoBBoozrACeIQITHi73DB1kSQdbfOfb_nuo26PEaIgvsncj-he0v.y3mcOAn4nXDleSobp2eQYg';

        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'ECDH-ES+A256KW');
        $payload = json_decode($test_jwe->getPlaintext(), true);

        $this->assertEquals('0607a317-044c-49dc-83ea-89bbf7766c03', $payload['refreshToken']);
        $this->assertEquals('c8945473-6217-4ec7-a543-09371ee156e3', $payload['authToken']);
    }


    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    public function testEncryptedKeyFailure() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
            $this->expectExceptionCode(InvalidTokenException::DECRYPTION_ERROR);
        }

        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOg.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    public function testIVFailure() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
            $this->expectExceptionCode(InvalidTokenException::DECRYPTION_ERROR);
        }

        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZg.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    public function testTagFailure() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
            $this->expectExceptionCode(InvalidTokenException::DECRYPTION_ERROR);
        }

        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVg';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    public function testCrit() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
            $this->expectExceptionCode(InvalidTokenException::UNSUPPORTED_ERROR);
        }

        $private_set = $this->getPrivateKeySet();
        $token = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3JpdCI6WyJ4LXVua25vd24tY3JpdGljYWwiXSwieC11bmtub3duLWNyaXRpY2FsIjp0cnVlfQ.sJFRqh6iiJh2OykXQYQ3GI1NZKC6jDwkc3k9959k6AwIbOMZ41ELjQ.wyDWTBKJiewaNP0YOM8uWQ.obEeoNob7fepPaWGNZqVgh6qEMK9qsIWPQtMf0tI_-U.enkNNlZhspYfLmeWpXA2dg';
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    function testInvalidToken() {
        
        if (method_exists($this, 'expectException')) {
            $this->expectException('\InvalidArgumentException');
        }

        $invalid_token = '12345';
        $dummy_set = $this->getPrivateKeySet();

        $result = JWE::decrypt($invalid_token, $dummy_set, 'dummy');
    }

    /**
     * @expectedException SimpleJWT\InvalidTokenException
     */
    function testMultiNoDecryptableRecipient() {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SimpleJWT\InvalidTokenException');
            $this->expectExceptionCode(InvalidTokenException::DECRYPTION_ERROR);
        }

        $private_set = new KeySet();
        $test_jwe = JWE::decrypt($this->multi_token, $private_set, 'A128KW');
    }
}
