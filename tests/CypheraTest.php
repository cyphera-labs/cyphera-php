<?php

declare(strict_types=1);

namespace Cyphera\Tests;

use Cyphera\Cyphera;
use PHPUnit\Framework\TestCase;

class CypheraTest extends TestCase
{
    private static function createClient(): Cyphera
    {
        return Cyphera::fromConfig([
            'configurations' => [
                'ssn' => ['engine' => 'ff1', 'key_ref' => 'test-key', 'header' => 'T01'],
                'ssn_digits' => ['engine' => 'ff1', 'alphabet' => 'digits', 'header_enabled' => false, 'key_ref' => 'test-key'],
                'ssn_mask' => ['engine' => 'mask', 'pattern' => 'last4', 'header_enabled' => false],
                'ssn_hash' => ['engine' => 'hash', 'algorithm' => 'sha256', 'key_ref' => 'test-key', 'header_enabled' => false],
            ],
            'keys' => [
                'test-key' => ['material' => '2B7E151628AED2A6ABF7158809CF4F3C'],
            ],
        ]);
    }

    public function testProtectAccessWithHeader(): void
    {
        $c = self::createClient();
        $protected = $c->protect('123456789', 'ssn');
        $this->assertStringStartsWith('T01', $protected);
        $this->assertGreaterThan(strlen('123456789'), strlen($protected));
        $accessed = $c->access($protected);
        $this->assertSame('123456789', $accessed);
    }

    public function testProtectAccessWithPassthroughs(): void
    {
        $c = self::createClient();
        $protected = $c->protect('123-45-6789', 'ssn');
        $this->assertStringContainsString('-', $protected);
        $accessed = $c->access($protected);
        $this->assertSame('123-45-6789', $accessed);
    }

    public function testHeaderlessDigitsRoundtrip(): void
    {
        $c = self::createClient();
        $protected = $c->protect('123456789', 'ssn_digits');
        $this->assertSame(9, strlen($protected));
        $accessed = $c->access($protected, 'ssn_digits');
        $this->assertSame('123456789', $accessed);
    }

    public function testDeterministic(): void
    {
        $c = self::createClient();
        $a = $c->protect('123456789', 'ssn');
        $b = $c->protect('123456789', 'ssn');
        $this->assertSame($a, $b);
    }

    public function testMaskLast4(): void
    {
        $c = self::createClient();
        $result = $c->protect('123-45-6789', 'ssn_mask');
        $this->assertSame('*******6789', $result);
    }

    public function testHashDeterministic(): void
    {
        $c = self::createClient();
        $a = $c->protect('123-45-6789', 'ssn_hash');
        $b = $c->protect('123-45-6789', 'ssn_hash');
        $this->assertSame($a, $b);
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $a);
    }

    public function testAccessNonreversibleRaises(): void
    {
        $c = self::createClient();
        $masked = $c->protect('123-45-6789', 'ssn_mask');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/No matching header/');
        $c->access($masked);
    }

    public function testHeaderCollisionRaises(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Header collision/');
        Cyphera::fromConfig([
            'configurations' => [
                'a' => ['engine' => 'ff1', 'key_ref' => 'k', 'header' => 'ABC'],
                'b' => ['engine' => 'ff1', 'key_ref' => 'k', 'header' => 'ABC'],
            ],
            'keys' => ['k' => ['material' => '2B7E151628AED2A6ABF7158809CF4F3C']],
        ]);
    }

    public function testHeaderRequiredRaises(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/no header specified/');
        Cyphera::fromConfig([
            'configurations' => ['a' => ['engine' => 'ff1', 'key_ref' => 'k']],
            'keys' => ['k' => ['material' => '2B7E151628AED2A6ABF7158809CF4F3C']],
        ]);
    }

    public function testCrossLanguageVector(): void
    {
        $c = self::createClient();
        $result = $c->protect('123-45-6789', 'ssn');
        $this->assertSame('T01i6J-xF-07pX', $result);
    }
}
