<?php

namespace Sjord\Fecid;

use \Exception;

function sha256($msg) {
    return hash('sha256', $msg, true);
}

function kdf($key, $msg) {
    return hash_hmac('sha256', $msg, $key, true);
}

function rf($key, $msg) {
    $digest = kdf($key, pack('P', $msg));
    $result = unpack('P', substr($digest, 0, 6) . "\x00\x00")[1] & 0x1FFFFFFFFFF;
    return $result;
}

class Fecid {
    public $rounds = 22;
    public $round_keys = [];

    public function __construct($key) {
        assert(strlen($key) >= 32);
        $key = sha256($key);
        for ($i = 0; $i < $this->rounds; $i++) {
            $this->round_keys[] = kdf($key, str_repeat(pack('P', $i), 8));
        }
    }

    public function encrypt($val, $tweak = "") {
        $left = ($val >> 23) & 0x1FFFFFFFE00;
        $right = $val & 0xFFFFFFFF;

        for ($i = 0; $i < 2; $i++) {
            list($left, $right) = [$right, $left ^ rf(kdf($this->round_keys[$i], $tweak), $right)];
        }

        for ($i = 2; $i < $this->rounds - 2; $i++) {
            list($left, $right) = [$right, $left ^ rf($this->round_keys[$i], $right)];
        }

        for ($i = $this->rounds - 2; $i < $this->rounds; $i++) {
            list($left, $right) = [$right, $left ^ rf(kdf($this->round_keys[$i], $tweak), $right)];
        }

        return Base58::encode($left) . Base58::encode($right);
    }

    public function decrypt($val, $tweak = "") {
        $left = Base58::decode(substr($val, 0, 7));
        $right = Base58::decode(substr($val, 7));

        for ($i = $this->rounds - 1; $i >= $this->rounds - 2; $i--) {
            list($left, $right) = [$right ^ rf(kdf($this->round_keys[$i], $tweak), $left), $left];
        }

        for ($i = $this->rounds - 3; $i >= 2; $i--) {
            list($left, $right) = [$right ^ rf($this->round_keys[$i], $left), $left];
        }

        for ($i = 1; $i >= 0; $i--) {
            list($left, $right) = [$right ^ rf(kdf($this->round_keys[$i], $tweak), $left), $left];
        }

        $left_zeroes = $left & ~0x1FFFFFFFE00;
        $right_zeroes = $right & ~0xFFFFFFFF;
        if ($left_zeroes || $right_zeroes) {
            throw new Exception("invalid ciphertext");
        }

        return ($left << 23) ^ $right;
    }
}
