<?php

namespace Sjord\Fecid;

use \Exception;

final class Base58 {

    static $alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static $max_int = 0x1ffffffffff;
    static $max_token = "zmM9z4E";

    public static function encode($input) {
        global $alphabet, $max_int;
        if ($input < 0 || $input > static::$max_int) {
            throw new Exception("Expected integer between 0 and " . $max_int . ", got " . $input);
        }

        $result = "";
        $num = $input;
        for ($i = 0; $i < 7; $i++) {
            $rem = $num % 58;
            $num = intdiv($num, 58);
            $result = static::$alphabet[$rem] . $result;
        }
        assert($num == 0);
        return $result;
    }

    public static function decode($input) {
        if (strlen($input) != 7) {
            throw new Exception("Expected token of length 7, got token of length " . strlen($input));
        }

        if ($input > static::$max_token) {
            throw new Exception("Token is too big to decode into a 64-bit integer");
        }

        $result = 0;
        for ($i = 0; $i < strlen($input); $i++) {
            $result *= 58;
            $index = strpos(static::$alphabet, $input[$i]);
            $result += $index;
        }
        return $result;
    }
}
