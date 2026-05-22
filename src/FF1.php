<?php

declare(strict_types=1);

namespace Cyphera;

/**
 * FF1 Format-Preserving Encryption (NIST SP 800-38G).
 */
class FF1
{
    private string $key;
    private string $tweak;
    private string $alphabet;
    private int $radix;
    /** @var array<string, int> */
    private array $charMap;

    public function __construct(string $key, string $tweak, string $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        $keyLen = strlen($key);
        if ($keyLen !== 16 && $keyLen !== 24 && $keyLen !== 32) {
            throw new \InvalidArgumentException("Key must be 16, 24, or 32 bytes, got {$keyLen}");
        }
        if (mb_strlen($alphabet) < 2) {
            throw new \InvalidArgumentException('Alphabet must have >= 2 characters');
        }

        $this->key = $key;
        $this->tweak = $tweak;
        $this->alphabet = $alphabet;
        $this->radix = mb_strlen($alphabet);
        $this->charMap = [];
        foreach (mb_str_split($alphabet) as $i => $c) {
            $this->charMap[$c] = $i;
        }
    }

    public function encrypt(string $plaintext): string
    {
        $digits = $this->toDigits($plaintext);
        $result = $this->ff1Encrypt($digits, $this->tweak);
        return $this->fromDigits($result);
    }

    public function decrypt(string $ciphertext): string
    {
        $digits = $this->toDigits($ciphertext);
        $result = $this->ff1Decrypt($digits, $this->tweak);
        return $this->fromDigits($result);
    }

    /** @return int[] */
    private function toDigits(string $s): array
    {
        $digits = [];
        foreach (mb_str_split($s) as $c) {
            if (!isset($this->charMap[$c])) {
                throw new \InvalidArgumentException("Character '{$c}' not in alphabet");
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

    private function prf(string $data): string
    {
        $y = str_repeat("\x00", 16);
        for ($off = 0; $off < strlen($data); $off += 16) {
            $block = $y ^ substr($data, $off, 16);
            $y = $this->aesEcb($block);
        }
        return $y;
    }

    private function expandS(string $R, int $d): string
    {
        $blocks = intdiv($d + 15, 16);
        $out = $R;
        for ($j = 1; $j < $blocks; $j++) {
            $x = str_repeat("\x00", 12) . pack('N', $j);
            // XOR with R (not previous block) per NIST SP 800-38G
            $x = $x ^ $R;
            $out .= $this->aesEcb($x);
        }
        return substr($out, 0, $d);
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

    // NIST SP 800-38G: length >= 2 and radix^length >= 1,000,000.
    private function checkLength(int $n): void
    {
        if ($n < 2 || gmp_cmp(gmp_pow($this->radix, $n), 1000000) < 0) {
            throw new \InvalidArgumentException(
                'input too short (NIST minimum: length >= 2 and radix^length >= 1,000,000)'
            );
        }
    }

    private function computeB(int $v): int
    {
        // NIST SP 800-38G: b = ceil(ceil(v*log2(radix))/8) with exact integer
        // arithmetic. ceil(v*log2(radix)) is the bit length of radix^v - 1.
        // Floating-point log2 is forbidden — rounding errors corrupt ciphertext.
        $pow = gmp_sub(gmp_pow($this->radix, $v), 1);
        $bits = (gmp_cmp($pow, 0) === 0) ? 1 : strlen(gmp_strval($pow, 2));
        return intdiv($bits + 7, 8);
    }

    private function buildP(int $u, int $n, int $t): string
    {
        return pack('C8', 1, 2, 1, ($this->radix >> 16) & 0xFF, ($this->radix >> 8) & 0xFF, $this->radix & 0xFF, 10, $u)
            . pack('N', $n)
            . pack('N', $t);
    }

    private function buildQ(string $T, int $i, string $numBytes, int $b): string
    {
        $pad = (16 - ((strlen($T) + 1 + $b) % 16)) % 16;
        $q = $T . str_repeat("\x00", $pad) . chr($i);
        $numLen = strlen($numBytes);
        if ($numLen < $b) {
            $q .= str_repeat("\x00", $b - $numLen);
        }
        $start = max(0, $numLen - $b);
        $q .= substr($numBytes, $start);
        return $q;
    }

    private function gmpToBytes(\GMP $val, int $len): string
    {
        // Use gmp_export rather than gmp_strval(…,16)+hex2bin: the latter
        // round-trips through ASCII text, and when the result happens to be the
        // single byte 0x30 ('0'), PHP's Elvis operator treated it as falsy and
        // replaced it with NUL — silently corrupting the FF1 Q block.
        if (gmp_cmp($val, 0) === 0) {
            return str_repeat("\x00", $len > 0 ? $len : 1);
        }
        $bytes = gmp_export($val, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        if (strlen($bytes) < $len) {
            $bytes = str_repeat("\x00", $len - strlen($bytes)) . $bytes;
        }
        if (strlen($bytes) > $len) {
            $bytes = substr($bytes, -$len);
        }
        return $bytes;
    }

    /**
     * @param int[] $pt
     * @return int[]
     */
    private function ff1Encrypt(array $pt, string $T): array
    {
        $n = count($pt);
        $this->checkLength($n);
        $u = intdiv($n, 2);
        $v = $n - $u;
        $A = array_slice($pt, 0, $u);
        $B = array_slice($pt, $u);

        $b = $this->computeB($v);
        $d = 4 * intdiv($b + 3, 4) + 4;
        $P = $this->buildP($u, $n, strlen($T));

        for ($i = 0; $i < 10; $i++) {
            $numB = $this->gmpToBytes($this->num($B), max($b, 1));
            $Q = $this->buildQ($T, $i, $numB, $b);
            $R = $this->prf($P . $Q);
            $S = $this->expandS($R, $d);
            $y = gmp_import($S, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

            $m = ($i % 2 === 0) ? $u : $v;
            $c = gmp_mod(gmp_add($this->num($A), $y), gmp_pow($this->radix, $m));
            $A = $B;
            $B = $this->str($c, $m);
        }

        return array_merge($A, $B);
    }

    /**
     * @param int[] $ct
     * @return int[]
     */
    private function ff1Decrypt(array $ct, string $T): array
    {
        $n = count($ct);
        $this->checkLength($n);
        $u = intdiv($n, 2);
        $v = $n - $u;
        $A = array_slice($ct, 0, $u);
        $B = array_slice($ct, $u);

        $b = $this->computeB($v);
        $d = 4 * intdiv($b + 3, 4) + 4;
        $P = $this->buildP($u, $n, strlen($T));

        for ($i = 9; $i >= 0; $i--) {
            $numA = $this->gmpToBytes($this->num($A), max($b, 1));
            $Q = $this->buildQ($T, $i, $numA, $b);
            $R = $this->prf($P . $Q);
            $S = $this->expandS($R, $d);
            $y = gmp_import($S, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

            $m = ($i % 2 === 0) ? $u : $v;
            $mod = gmp_pow($this->radix, $m);
            $c = gmp_mod(gmp_add(gmp_sub($this->num($B), $y), gmp_mul($mod, gmp_init(2))), $mod);
            // Proper modular subtraction: ((numB - y) % mod + mod) % mod
            $c = gmp_mod(gmp_sub($this->num($B), $y), $mod);
            if (gmp_sign($c) < 0) {
                $c = gmp_add($c, $mod);
            }
            $B = $A;
            $A = $this->str($c, $m);
        }

        return array_merge($A, $B);
    }
}
