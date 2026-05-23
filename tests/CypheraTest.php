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
        // ssn_digits has header_enabled=false, so the 2-arg access form
        // (escape hatch) is the way to round-trip without a header to key off.
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
        // ssn_mask has header_enabled=false, so access() can't find a header
        // and reports the no-matching-header error.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('no matching header found');
        $c->access($masked);
    }

    public function testHeaderCollisionRaises(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('configuration error: header collision');
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
        $this->expectExceptionMessage('configuration error: header must be specified');
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

    public function testTwoArgAccessOnIrreversibleConfigurationRaises(): void
    {
        $c = self::createClient();
        // The 2-arg escape hatch is permissive about header_enabled but
        // still must refuse mask/hash configurations — those are one-way.
        $masked = $c->protect('123-45-6789', 'ssn_mask');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("cannot reverse 'ssn_mask' — mask is irreversible");
        $c->access($masked, 'ssn_mask');
    }

    // ── Strict FF3 / FF3-1 tweak (no silent zero-fill) ──

    public function testFf3MissingTweakRaises(): void
    {
        $c = Cyphera::fromConfig([
            'configurations' => [
                'ff3_no_tweak' => ['engine' => 'ff3', 'alphabet' => 'digits', 'key_ref' => 'k', 'header' => 'T03'],
            ],
            'keys' => ['k' => ['material' => '2B7E151628AED2A6ABF7158809CF4F3C']],
        ]);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("configuration 'ff3_no_tweak' is missing required 'tweak' (FF3 needs 8 bytes)");
        $c->protect('123456789', 'ff3_no_tweak');
    }

    public function testFf31MissingTweakRaises(): void
    {
        $c = Cyphera::fromConfig([
            'configurations' => [
                'ff31_no_tweak' => ['engine' => 'ff31', 'alphabet' => 'digits', 'key_ref' => 'k', 'header' => 'T04'],
            ],
            'keys' => ['k' => ['material' => '2B7E151628AED2A6ABF7158809CF4F3C']],
        ]);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("configuration 'ff31_no_tweak' is missing required 'tweak' (FF3-1 needs 7 bytes)");
        $c->protect('123456789', 'ff31_no_tweak');
    }

    public function testFf3WithExplicitTweakRoundtrips(): void
    {
        $c = Cyphera::fromConfig([
            'configurations' => [
                'ff3_ok' => ['engine' => 'ff3', 'alphabet' => 'digits', 'key_ref' => 'k', 'header' => 'T05', 'tweak' => 'D8E7920AFA330A73'],
            ],
            'keys' => ['k' => ['material' => '2B7E151628AED2A6ABF7158809CF4F3C']],
        ]);
        $protected = $c->protect('123456789', 'ff3_ok');
        $this->assertNotSame('123456789', $protected);
        $this->assertSame('123456789', $c->access($protected));
    }

    public function testFf1MissingTweakStillWorks(): void
    {
        // FF1 tweak stays optional per NIST SP 800-38G.
        $c = self::createClient();
        $protected = $c->protect('123456789', 'ssn'); // ssn is ff1 with no tweak
        $this->assertSame('123456789', $c->access($protected));
    }
}
