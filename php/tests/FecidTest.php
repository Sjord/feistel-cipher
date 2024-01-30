<?php
use PHPUnit\Framework\TestCase;
use Sjord\Fecid\Fecid;

final class FecidTest extends TestCase {
    public function testEncryptDecrypt() {
        $key = str_repeat('a', 32);
        $tweak = 'tweak';

        $fecid = new Fecid($key);

        for ($i = 0; $i < 0x7FFFFFFFFFFFFFFF; $i += 0x50505050505050) {
            $ciphertext = $fecid->encrypt($i, $tweak);
            $plaintext = $fecid->decrypt($ciphertext, $tweak);
            $this->assertEquals($i, $plaintext);
        }
    }

    public function testDifferentTweak() {
        $key = str_repeat('a', 32);
        $fecid = new Fecid($key);
        $this->assertNotEquals($fecid->encrypt(123, 'a'), $fecid->encrypt(123, 'b'));
    }
}
