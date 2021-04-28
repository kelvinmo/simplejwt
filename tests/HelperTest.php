<?php

namespace SimpleJWT;

use SimpleJWT\Util\Helper;
use PHPUnit\Framework\TestCase;


class HelperTest extends TestCase {

    function testJWSCompact() {
        $compact = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        $results = Helper::detect($compact);
        $this->assertEquals('JWT', $results['type']);
        $this->assertEquals(Helper::COMPACT_FORMAT, $results['format']);
    }

    function testJWSJSON() {
        $complete_json = <<<END
        {"payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        "signatures":[
        {"protected":"eyJhbGciOiJSUzI1NiJ9",
        "header":
         {"kid":"2010-12-29"},
        "signature":
         "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},
        {"protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":
         {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "signature":
         "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}]
        }
END;

        $results = Helper::detect($complete_json);
        $this->assertEquals('JWT', $results['type']);
        $this->assertEquals(Helper::JSON_FORMAT, $results['format']);

        $flattened_json = <<<END
        {
        "payload":
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        "protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":
        {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "signature":
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        }
END;

        $results = Helper::detect($flattened_json);
        $this->assertEquals('JWT', $results['type']);
        $this->assertEquals(Helper::JSON_FORMAT, $results['format']);
    }

    function testJWECompact() {
        $compact = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ';

        $results = Helper::detect($compact);
        $this->assertEquals('JWE', $results['type']);
        $this->assertEquals(Helper::COMPACT_FORMAT, $results['format']);
    }

    function testJWEJSON() {
        $complete_json = <<<END
        {
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
        "iv":
        "AxY8DCtDaGlsbGljb3RoZQ",
        "ciphertext":
        "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
        "tag":
        "Mz-VPPyU4RlcuYv1IwIvzw"
        }
END;

        $results = Helper::detect($complete_json);
        $this->assertEquals('JWE', $results['type']);
        $this->assertEquals(Helper::JSON_FORMAT, $results['format']);

        $flattened_json = <<<END
        {
        "protected":
        "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
        "unprotected":
        {"jku":"https://server.example.com/keys.jwks"},
        "header":
        {"alg":"A128KW","kid":"7"},
        "encrypted_key":
        "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        "iv":
        "AxY8DCtDaGlsbGljb3RoZQ",
        "ciphertext":
        "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
        "tag":
        "Mz-VPPyU4RlcuYv1IwIvzw"
        }
END;

        $results = Helper::detect($flattened_json);
        $this->assertEquals('JWE', $results['type']);
        $this->assertEquals(Helper::JSON_FORMAT, $results['format']);
    }

    function testInvalidToken() {
        $invalid_token = '12345';

        $result = Helper::detect($invalid_token);
        $this->assertNull($result);
    }
}
