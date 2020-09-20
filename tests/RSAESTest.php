<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;
use SimpleJWT\Keys\KeySet;
use SimpleJWT\Keys\RSAKey;
use PHPUnit\Framework\TestCase;

class RSAESTest extends TestCase {
    function testRSA1_5() {
        $cek = base64_decode('BNMfxVSd/P4LZJ36P6pqzmt81C1vawnbyLHwj5wszw==');

        $private_set = new KeySet();
        $private_set->add(new RSAKey([
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

        $public_set = new KeySet();
        $public_set->add($private_set->getById('rsa1_5')->getPublicKey());

        $headers = [];

        $alg = new RSAES('RSA1_5');
        $encrypted_key = $alg->encryptKey($cek, $public_set, $headers);

        $new_cek = $alg->decryptKey($encrypted_key, $private_set, $headers);
        $this->assertEquals(base64_encode($cek), base64_encode($new_cek));
    }

    function testRSAOAEP() {
        $cek = base64_decode('saH0gFSP4XM/tAP/a5rU9ooHbltwLiJpL4LLLnrqQPw=');

        $private_set = new KeySet();
        $private_set->add(new RSAKey([
            "kty" => "RSA",
            "kid" => "rsa-oaep",
            "n" => "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
            "e" => "AQAB",
            "d" => "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
            "p" => "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
            "q" => "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
            "dp" => "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
            "dq" => "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
            "qi" => "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
        ], 'php'));

        $public_set = new KeySet();
        $public_set->add($private_set->getById('rsa-oaep')->getPublicKey());

        $headers = [];

        $alg = new RSAES('RSA-OAEP');
        $encrypted_key = $alg->encryptKey($cek, $public_set, $headers);

        $new_cek = $alg->decryptKey($encrypted_key, $private_set, $headers);
        $this->assertEquals(base64_encode($cek), base64_encode($new_cek));
    }


    function testRSAOAEP256() {
        $cek = base64_decode('VIWbNCxJ6io=');

        $private_set = new KeySet();
        $private_set->add(new RSAKey([
            "kty" => "RSA",
            "kid" => "rsa-oaep-256",
            "n" => "pylWkxVbGBO7hId_tFNDVW4FaAQ95ZEIcqOlGMwR4j4tt06vRUUGjE49JYonGPus3MPq-kV2lblX6I-_EQrtBJqZLZxDAjLQLzUpxno0GZNeqbVp-FsbzTfea4mc1iaX6EMTD_BSnQnJfYE8sV8pN1H_VvlD-9q7Y5ccx_T21b_xWUQWsfWQe95ahKRPmALvKbQ72hlg-Uj4r7h2bBq4DTLuyI7WbQtlrr5EptCzxeCrBRqqG5EvvMF7jnUd3sxTZbbbbasAIMMFfbQBOlEhOleYo6q2eYWw9NiGJ6VKDz8ChfvLSv3-tlyxU69mglZW1DI4t1UDIxUAdT9OQh48Vw",
            "e" => "AQAB",
            "d" => "ZdrVasffertDTky17q2xYJOqbafwAzqtOBUomwR1fTK_7mred0nI5KMjtQUKL7niqZ4jRp4e1Lpbq1QzavIKW_zLizQkzGkj2y_8pXh-2HqoeqYUzQTO2uvI9iOi0gYwF5EPQ23_GLsG8BdYYQeH-LJY8Kjv2L194wAHxHsqEDFpbH1lI7wZHU2RiSen4LCVhO0gW9L_T8Q4JnjfgjU_dTKzu7gdaePzkHCu0_tk_OAyoIno5klVr6UhOm6yQSMb2Y1wL7pyWpsgWVL9oYZBLZ4Nk0TSmYxFWtjCuuhe5nJ1FGbVKIMEAytbfgL35VjHr4LH-_WO6gu07w8AHmzQqQ",
            "p" => "1P2aw0dPuDqvgyRwZDYJZZ5RGzImMrI5tojzzSqth1J9bPZS-5ycpnlA6EeJRE8umbDLDPq71N6VOWEGyGXzji-3uCsjEmCpTfDgF1a_c84DhoaNnEFkVWCoGvL1PBjk983z1R2AJnNy5uAhavv2f2VclFB2nMpJTk9mMbI5zhs",
            "q" => "yOqg4qGzpEEqcCvM2pP00VDaYNc2yZx8Vm_epN0bQBy8DYwGParwtXmVPTY0OqGLM9v4uerpRFJJDMkFJF-Pe54psaKIvGZzGinh3RpFyf1_gjj_cnrcSf_3OZHQ3AliBrnToI9h50YuK4BNeMuMXszbm3-9Ktao_qRsEFPhvnU",
            "dp" => "EO3LVEQhwPnhI2JNEJn-6zXHKos04Aisb6a5AhCnVD8pOvTlKZyMEutGTnAJKAXHJW4Y5YI0VboPUE029cysrBt81cWP9xD5w_kmRpSdiP3R5-pf7RCBggu5sNKozUsJP-z9uW2r1uKMOm-MGG3IbN3Imv0-QD4Pz4qeC8snrws",
            "dq" => "l_wlSEtaQV6qY8A-bvqNr-mhyLAE2e5ugFSP79byzkTuXLEX535wKFeY9X0TdWbOjqRQOxPg8bXtXKaUJTfEqpayo5V4Kky1tY0JNuCw-mOxGSlU05ztF21x7zLG9CyE4uGfnU3ZmcIVGwMrl70iqnP9jFvNFaLcpARtWsyZcCE",
            "qi" => "S7gGTh7_fp78PEV4_O21nKSu8Jk6gxLf3LGz3s9FiqZlDT0IZvFDy_DTgl6TgRgRcKChZR7vzX3veGuOs1ZVXZ-gfIW19cvddDgvESm142tBZrbMkVeSNplwhkghLEhJWDUf3JzxTyGNvn-_fL2TogmkaB_iPOtEurZ9ZvRdHJ0"
        ], 'php'));

        $public_set = new KeySet();
        $public_set->add($private_set->getById('rsa-oaep-256')->getPublicKey());

        $headers = [];

        $alg = new RSAES('RSA-OAEP-256');
        $encrypted_key = $alg->encryptKey($cek, $public_set, $headers);

        $new_cek = $alg->decryptKey($encrypted_key, $private_set, $headers);
        $this->assertEquals(base64_encode($cek), base64_encode($new_cek));
    }
}

?>
