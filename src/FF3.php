<?php

declare(strict_types=1);

namespace Cyphera;

/**
 * FF3 (NIST SP 800-38G) Format-Preserving Encryption.
 *
 * This is the original FF3, which is cryptographically weak and deprecated.
 * Use {@see FF31} (FF3-1, NIST SP 800-38G Rev 1) instead.
 */
class FF3
{
    private string $key;
    private string $tweak;
    private string $alphabet;
    private int $radix;
    private int $maxLen;
    /** @var array<string, int> */
    private array $charMap;

    public function __construct(string $key, string $tweak, string $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        $keyLen = strlen($key);
        if ($keyLen !== 16 && $keyLen !== 24 && $keyLen !== 32) {
            throw new \InvalidArgumentException("invalid key length: {$keyLen} (expected 16, 24, or 32)");
        }
        $tweakLen = strlen($tweak);
        if ($tweakLen !== 8) {
            throw new \InvalidArgumentException("invalid tweak length: {$tweakLen} (expected 8)");
        }
        if (mb_strlen($alphabet) < 2) {
            throw new \InvalidArgumentException('Alphabet must have >= 2 characters');
        }

        // FF3 reverses the key
        $this->key = strrev($key);
        $this->tweak = $tweak;
        $this->alphabet = $alphabet;
        $this->radix = mb_strlen($alphabet);
        $this->charMap = [];
        foreach (mb_str_split($alphabet) as $i => $c) {
            $this->charMap[$c] = $i;
        }
        // NIST FF3 maximum length: 2 * floor(log_radix(2^96)), exact arithmetic.
        $limit = gmp_pow(2, 96);
        $k = 0;
        while (gmp_cmp(gmp_pow($this->radix, $k + 1), $limit) <= 0) {
            $k++;
        }
        $this->maxLen = 2 * $k;
    }

    // NIST SP 800-38G: length >= 2, radix^length >= 1,000,000, length <= maxLen.
    private function checkLength(int $n): void
    {
        if ($n < 2 || gmp_cmp(gmp_pow($this->radix, $n), 1000000) < 0) {
            throw new \InvalidArgumentException(
                'input too short (NIST minimum: length >= 2 and radix^length >= 1,000,000)'
            );
        }
        if ($n > $this->maxLen) {
            throw new \InvalidArgumentException(
                "input too long (FF3 maximum for this radix is {$this->maxLen})"
            );
        }
    }

    public function encrypt(string $plaintext): string
    {
        $digits = $this->toDigits($plaintext);
        $result = $this->ff3Encrypt($digits);
        return $this->fromDigits($result);
    }

    public function decrypt(string $ciphertext): string
    {
        $digits = $this->toDigits($ciphertext);
        $result = $this->ff3Decrypt($digits);
        return $this->fromDigits($result);
    }

    /** @return int[] */
    private function toDigits(string $s): array
    {
        $digits = [];
        foreach (mb_str_split($s) as $i => $c) {
            if (!isset($this->charMap[$c])) {
                throw new \InvalidArgumentException("invalid char '{$c}' at position {$i}");
            }
            $digits[] = $this->charMap[$c];
        }
        return $digits;
    }

    /** @param int[] $d */
    private function fromDigits(array $d): string
    {
        $chars = mb_str_split($this->alphabet);
        return implode('', array_map(fn(int $i) => $chars[$i], $d));
    }

    private function aesEcb(string $block): string
    {
        // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
        // This is single-block encryption used as a building block, not ECB mode applied to user data.
        $algo = match (strlen($this->key)) {
            16 => 'aes-128-ecb',
            24 => 'aes-192-ecb',
            32 => 'aes-256-ecb',
        };
        return openssl_encrypt($block, $algo, $this->key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
    }

    /** @param int[] $digits */
    private function num(array $digits): \GMP
    {
        $r = gmp_init(0);
        $radix = gmp_init($this->radix);
        foreach ($digits as $d) {
            $r = gmp_add(gmp_mul($r, $radix), gmp_init($d));
        }
        return $r;
    }

    /** @return int[] */
    private function str(\GMP $num, int $len): array
    {
        $r = array_fill(0, $len, 0);
        $radix = gmp_init($this->radix);
        for ($i = $len - 1; $i >= 0; $i--) {
            [$num, $rem] = gmp_div_qr($num, $radix);
            $r[$i] = gmp_intval($rem);
        }
        return $r;
    }

    /** @param int[] $half */
    private function calcP(int $round, string $w, array $half): \GMP
    {
        $inp = str_repeat("\x00", 16);
        $inp[0] = $w[0];
        $inp[1] = $w[1];
        $inp[2] = $w[2];
        $inp[3] = chr(ord($w[3]) ^ $round);

        $revHalf = array_reverse($half);
        $halfNum = $this->num($revHalf);
        $halfHex = gmp_strval($halfNum, 16);
        if (strlen($halfHex) % 2 !== 0) {
            $halfHex = '0' . $halfHex;
        }
        $halfBytes = hex2bin($halfHex) ?: "\x00";

        if (strlen($halfBytes) <= 12) {
            $pos = 16 - strlen($halfBytes);
            for ($k = 0; $k < strlen($halfBytes); $k++) {
                $inp[$pos + $k] = $halfBytes[$k];
            }
        } else {
            $start = strlen($halfBytes) - 12;
            for ($k = 0; $k < 12; $k++) {
                $inp[4 + $k] = $halfBytes[$start + $k];
            }
        }

        $revInp = strrev($inp);
        $aesOut = $this->aesEcb($revInp);
        $revOut = strrev($aesOut);
        return gmp_import($revOut, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }

    /**
     * @param int[] $pt
     * @return int[]
     */
    private function ff3Encrypt(array $pt): array
    {
        $n = count($pt);
        $this->checkLength($n);
        $u = intdiv($n + 1, 2);
        $v = $n - $u;
        $A = array_slice($pt, 0, $u);
        $B = array_slice($pt, $u);

        for ($i = 0; $i < 8; $i++) {
            if ($i % 2 === 0) {
                $w = substr($this->tweak, 4, 4);
                $p = $this->calcP($i, $w, $B);
                $m = gmp_pow($this->radix, $u);
                $aNum = $this->num(array_reverse($A));
                $y = gmp_mod(gmp_add($aNum, $p), $m);
                $A = array_reverse($this->str($y, $u));
            } else {
                $w = substr($this->tweak, 0, 4);
                $p = $this->calcP($i, $w, $A);
                $m = gmp_pow($this->radix, $v);
                $bNum = $this->num(array_reverse($B));
                $y = gmp_mod(gmp_add($bNum, $p), $m);
                $B = array_reverse($this->str($y, $v));
            }
        }

        return array_merge($A, $B);
    }

    /**
     * @param int[] $ct
     * @return int[]
     */
    private function ff3Decrypt(array $ct): array
    {
        $n = count($ct);
        $this->checkLength($n);
        $u = intdiv($n + 1, 2);
        $v = $n - $u;
        $A = array_slice($ct, 0, $u);
        $B = array_slice($ct, $u);

        for ($i = 7; $i >= 0; $i--) {
            if ($i % 2 === 0) {
                $w = substr($this->tweak, 4, 4);
                $p = $this->calcP($i, $w, $B);
                $m = gmp_pow($this->radix, $u);
                $aNum = $this->num(array_reverse($A));
                $y = gmp_mod(gmp_sub($aNum, $p), $m);
                if (gmp_sign($y) < 0) {
                    $y = gmp_add($y, $m);
                }
                $A = array_reverse($this->str($y, $u));
            } else {
                $w = substr($this->tweak, 0, 4);
                $p = $this->calcP($i, $w, $A);
                $m = gmp_pow($this->radix, $v);
                $bNum = $this->num(array_reverse($B));
                $y = gmp_mod(gmp_sub($bNum, $p), $m);
                if (gmp_sign($y) < 0) {
                    $y = gmp_add($y, $m);
                }
                $B = array_reverse($this->str($y, $v));
            }
        }

        return array_merge($A, $B);
    }
}
