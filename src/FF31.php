<?php

declare(strict_types=1);

namespace Cyphera;

/**
 * FF3-1 Format-Preserving Encryption (NIST SP 800-38G Revision 1).
 *
 * FF3-1 is FF3 with a 56-bit (7-byte) tweak. The tweak is expanded into the
 * 64-bit form the FF3 round function consumes; everything downstream is
 * identical FF3. FF3-1 supersedes the original FF3, which is cryptographically
 * weak.
 */
class FF31
{
    private FF3 $inner;

    public function __construct(string $key, string $tweak, string $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        if (strlen($tweak) !== 7) {
            throw new \InvalidArgumentException(
                'FF3-1 tweak must be exactly 7 bytes (56 bits), got ' . strlen($tweak)
            );
        }
        $this->inner = new FF3($key, self::expandTweak($tweak), $alphabet);
    }

    /**
     * Expand the 56-bit FF3-1 tweak into the 64-bit tweak the FF3 round
     * function consumes (NIST SP 800-38G Rev 1), with bytes[0..4] = T_L and
     * bytes[4..8] = T_R.
     */
    private static function expandTweak(string $t): string
    {
        return $t[0] . $t[1] . $t[2]
            . chr(ord($t[3]) & 0xF0)
            . $t[4] . $t[5] . $t[6]
            . chr((ord($t[3]) & 0x0F) << 4);
    }

    public function encrypt(string $plaintext): string
    {
        return $this->inner->encrypt($plaintext);
    }

    public function decrypt(string $ciphertext): string
    {
        return $this->inner->decrypt($ciphertext);
    }
}
