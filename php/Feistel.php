<?php

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

class Cipher {
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
        $left = ($val >> 23) & 0xFFFFFFFF;
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

        return base58_encode($left) . base58_encode($right);
    }

    public function decrypt($val, $tweak = "") {
        $left = base58_decode(substr($val, 0, 7));
        $right = base58_decode(substr($val, 7));

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

// Base58 encoder and decoder functions
function base58_encode($int) {
    $alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    $base_count = strlen($alphabet);
    $encoded = '';
    while ($int >= $base_count) {
        $div = $int / $base_count;
        $mod = ($int - ($base_count * intval($div)));
        $encoded = $alphabet[$mod] . $encoded;
        $int = intval($div);
    }
    if ($int) $encoded = $alphabet[$int] . $encoded;
    return $encoded;
}

function base58_decode($base58) {
    $alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    $base_count = strlen($alphabet);
    $decoded = 0;
    $multi = 1;
    while (strlen($base58) > 0) {
        $digit = $base58[strlen($base58) - 1];
        $decoded += $multi * strpos($alphabet, $digit);
        $multi = $multi * $base_count;
        $base58 = substr($base58, 0, -1);
    }
    return $decoded;
}

// Testing
$key = "helloworld helloworld helloworld";
$tweak = "tweak";
$cipher = new Cipher($key);
var_dump($cipher->round_keys);
$value = 123456;
$encrypted = $cipher->encrypt($value, $tweak);
echo "Encrypted: " . $encrypted . "\n";
$decrypted = $cipher->decrypt($encrypted, $tweak);
echo "Decrypted: " . $decrypted . "\n";

$start = microtime(true);
for ($i = 0; $i < 1000; $i++) {
    $c = new Cipher($key);
    $c->decrypt($c->encrypt(123, $tweak), $tweak);
}
$stop = microtime(true);
echo(($stop - $start) . 'ms');
