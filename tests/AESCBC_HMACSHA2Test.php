<?php

namespace SimpleJWT\Crypt;

use SimpleJWT\Util\Util;
use PHPUnit\Framework\TestCase;

class AESCBC_HMACSHA2Test extends TestCase {

    protected function base64url($base64) {
        return Util::base64url_encode(base64_decode($base64));
    }

    function testA128() {
        $cek = base64_decode('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=');
        $plaintext = 'A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience';
        $iv = $this->base64url('GvOMLcK5b/3YZpQJI0G8BA==');
        $additional = 'The second principle of Auguste Kerckhoffs';

        $alg = new AESCBC_HMACSHA2('A128CBC-HS256');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('yA7foy3fOdXvAMC0aINCeaLkahuASfeS92v+VLkDqcmpSsm0etJlXF8Q+a73FCfi/G+bPzmaIhSJ8WNixwMjNgnUWsaYZOMyHPgpNaxAlshuEzMUxUAZ6Mp5gN+kuc8bOExIbzpUxRB4FY7l153ln7002Eiz1pVQpnZGNEQnreVLiFH/tZj3+AB0uUc8guLb'), $results['ciphertext']);
        $this->assertEquals($this->base64url('ZSw/o2sKfFsyGfqzowvBxA=='), $results['tag']);
    }

    function testA384() {
        $cek = base64_decode('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v');
        $plaintext = 'A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience';
        $iv = $this->base64url('GvOMLcK5b/3YZpQJI0G8BA==');
        $additional = 'The second principle of Auguste Kerckhoffs';

        $alg = new AESCBC_HMACSHA2('A192CBC-HS384');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('6mXaa1nmHttBm+YtGXEq5dMD7rUAUtDf1ml/dyJMjtsADSeb3BTBByZUvTCUQjDGV77UygyfSoRm8isibRdGIUv4z8JACt2fUSbkeWY/yQs77Xh6Lw/8vzkEvipkHVwhBb/lkbriOx10SeUy7vYKmsi7bGsB011JeHvNV+9ISSfygK3JGsDE55x7Ee/GAFTj'), $results['ciphertext']);
        $this->assertEquals($this->base64url('hJCsDliUm/5Rh11zP5OsIHUWgDnMxzPX'), $results['tag']);
    }

    function testA512() {
        $cek = base64_decode('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==');
        $plaintext = 'A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience';
        $iv = $this->base64url('GvOMLcK5b/3YZpQJI0G8BA==');
        $additional = 'The second principle of Auguste Kerckhoffs';

        $alg = new AESCBC_HMACSHA2('A256CBC-HS512');
        $results = $alg->encryptAndSign($plaintext, $cek, $additional, $iv);

        $this->assertEquals($this->base64url('Sv+qrbeMMcXaSxtZDRD/vT3Y1dMCQjUmkS2gN+y8x72CLDAd1nw3O8y1hK0+knnC5tEqE3S3fwd1U9+ClBBEazbr2XBmKWrmQn6nXC4IRqEaCcz1Nw3IC/7LrSjHPwmzo7deZiollEEK5Jay4uZgnjHm4CzIN/BT0h83/09RlQu+JjjQndekkwkwgG0HA7H2'), $results['ciphertext']);
        $this->assertEquals($this->base64url('TdO0wIin9FwhaDlkWyASvy5iaajFaoFtvBsmd2GVW8U='), $results['tag']);
    }
}
?>
