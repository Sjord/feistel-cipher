<?php

$alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
$max_int = 0x1ffffffffff;
$max_token = "zmM9z4E";

function encode($input) {
    global $alphabet, $max_int;
    if ($input < 0 || $input > $max_int) {
        throw new Exception("Expected integer between 0 and " . $max_int . ", got " . $input);
    }

    $result = "";
    $num = $input;
    for ($i = 0; $i < 7; $i++) {
        list($num, $rem) = divmod($num, 58);
        $result = $alphabet[$rem] . $result;
    }
    assert($num == 0);
    return $result;
}

function decode($input) {
    global $alphabet, $max_token;
    if (strlen($input) != 7) {
        throw new Exception("Expected token of length 7, got token of length " . strlen($input));
    }

    if ($input > $max_token) {
        throw new Exception("Token is too big to decode into a 64-bit integer");
    }

    $result = 0;
    for ($i = 0; $i < strlen($input); $i++) {
        $result *= 58;
        $index = strpos($alphabet, $input[$i]);
        $result += $index;
    }
    return $result;
}

// Helper function to mimic divmod in PHP
function divmod($a, $b) {
    $quotient = intval($a / $b);
    $remainder = $a % $b;
    return array($quotient, $remainder);
}

// Testing
$input = 123456;
$encoded = encode($input);
echo "Encoded: " . $encoded . "\n";
$decoded = decode($encoded);
echo "Decoded: " . $decoded . "\n";
