<?php

use SimpleJWT\Keys\KeySet;
use PHPUnit\Framework\TestCase;

class KeySetTest extends TestCase {
    private function getKeySet() {
        $keyset_data = [
            'keys' => [
                [
                    'kid' => 'oct1',
                    'kty' => 'oct',
                    'k' => '12345'
                ],
                [
                    'kid' => 'oct2',
                    'kty' => 'oct',
                    'k' => '67890',
                    'use' => 'enc'
                ],
                [
                    "kid" => "EC",
                    "kty" => "EC",
                    "crv" => "P-256",
                    "x" => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y" => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                    "d" => "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
                ]
            ]
        ];

        $keys = new KeySet();
        $keys->load(json_encode($keyset_data));
        return $keys;
    }

    function testMandatoryCriteria() {
        $keys = $this->getKeySet();
        $key = $keys->get(['kty' => 'EC']);
        $this->assertEquals('EC', $key->getKeyId());
    }

    function testMandatoryCriteriaWithMultipleResults() {
        $keys = $this->getKeySet();
        $key = $keys->get(['kty' => 'oct']);
        // The first key that is added to the set
        $this->assertEquals('oct1', $key->getKeyId());
    }

    function testMandatoryIfPresentCriteria() {
        $keys = $this->getKeySet();
        $key = $keys->get(['kty' => 'oct', '@use' => 'sig']);
        $this->assertEquals('oct1', $key->getKeyId());
    }

    function testOptionalCriteria() {
        $keys = $this->getKeySet();
        $key = $keys->get(['kty' => 'oct', '~use' => 'enc']);
        $this->assertEquals('oct2', $key->getKeyId());
    }
}
?>
