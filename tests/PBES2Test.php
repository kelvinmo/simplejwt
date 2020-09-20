<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class PBES2Test extends TestCase {

    protected function getKeySet($password) {
        return \SimpleJWT\Keys\KeySet::createFromSecret($password, 'bin');
    }

    function testPBES2Encrypt() {
        $cek = Util::base64url_decode('bxsZNEIdFE5csDjwQdBScKGDJDfK7LmsgReZwsMw_bY');

        $password = 'Thus from my lips, by yours, my sin is purged.';
        $keys = $this->getKeySet($password);

        $stub = $this->getMockBuilder('SimpleJWT\Crypt\PBES2')
            ->setMethods(['generateSaltInput'])->setConstructorArgs(['PBES2-HS256+A128KW'])->getMock();

        $stub->method('generateSaltInput')->willReturn(Util::base64url_decode('2WCTcJZ1Rvd_CJuJripQ1w'));
        $stub->setIterations(4096);

        $headers = ['alg' => 'PBES2-HS256+A128KW'];

        $encrypted_key = $stub->encryptKey($cek, $keys, $headers);

        $this->assertEquals(4096, $headers['p2c']);
        $this->assertEquals('2WCTcJZ1Rvd_CJuJripQ1w', $headers['p2s']);
        $this->assertEquals('TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA', $encrypted_key);
    }

    function testPBES2Decrypt() {
        $encrypted_key = 'TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA';

        $password = 'Thus from my lips, by yours, my sin is purged.';
        $keys = $this->getKeySet($password);

        $headers = [
            'alg' => 'PBES2-HS256+A128KW',
            'p2c' => 4096,
            'p2s' => '2WCTcJZ1Rvd_CJuJripQ1w'
        ];

        $alg = new PBES2('PBES2-HS256+A128KW');
        $cek = $alg->decryptKey($encrypted_key, $keys, $headers);

        $this->assertEquals('bxsZNEIdFE5csDjwQdBScKGDJDfK7LmsgReZwsMw_bY', Util::base64url_encode($cek));
    }
}

?>
