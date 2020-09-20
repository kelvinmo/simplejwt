<?php

namespace SimpleJWT;

use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\RSAKey;
use SimpleJWT\Keys\SymmetricKey;
use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;


class JWETest extends TestCase {
    protected function getPrivateKeySet() {
        $set = new KeySet();

        $set->add(new RSAKey([
            "kty" => "RSA",
            "kid" => "rsa1_5",
            "n" => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e" => "AQAB",
            "d" => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            "p" => "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            "q" => "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            "dp" => "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            "dq" => "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            "qi" => "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
        ], 'php'));

        $set->add(new SymmetricKey([
            "kty" => "oct",
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
        $plaintext = 'Live long and prosper.';

        $public_set = $this->getPublicKeySet();
        $jwe = new JWE(["alg" => "RSA1_5","enc" => "A128CBC-HS256"], $plaintext);
        $token = $jwe->encrypt($public_set);

        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'RSA1_5');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testDecryptAESKW() {
        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ';
        $private_set = $this->getPrivateKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'A128KW');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }

    public function testDecryptDirect() {
        $plaintext = 'Live long and prosper.';

        $token = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiWUkzRW9JSyJ9..h7LOWyYIlzq4BJV5V1vxhg.aZEMslyY-kybAWlb8hM6aWCocQ3TMghMhNwk4Meyjb4.IDEVZS1i76IHNSd5sAt7tA';
        $private_set = $this->getDirectKeySet();
        $test_jwe = JWE::decrypt($token, $private_set, 'dir');
        $this->assertEquals($plaintext, $test_jwe->getPlaintext());
    }
}
