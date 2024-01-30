<?php
use PHPUnit\Framework\TestCase;
use Sjord\Fecid\Base58;

final class Base58Test extends TestCase {
    public function testEncode() {
        $this->assertEquals(Base58::encode(0), "1111111");
        $this->assertEquals(Base58::encode(123456), "1111dhZ");
        $this->assertEquals(Base58::encode(0x1ffffffffff), "zmM9z4E");
    }

    public function testDecode() {
        $this->assertEquals(Base58::decode("1111111"), 0);
        $this->assertEquals(Base58::decode("1111dhZ"), 123456);
        $this->assertEquals(Base58::decode("zmM9z4E"), 0x1ffffffffff);
    }
}
