<?php

declare(strict_types=1);

namespace Cyphera\Tests;

use Cyphera\FF1;
use PHPUnit\Framework\TestCase;

class FF1NistTest extends TestCase
{
    private static function hex(string $h): string
    {
        return hex2bin($h);
    }

    public function testSample1(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3C'), '', '0123456789');
        $this->assertSame('2433477484', $c->encrypt('0123456789'));
        $this->assertSame('0123456789', $c->decrypt('2433477484'));
    }

    public function testSample2(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3C'), self::hex('39383736353433323130'), '0123456789');
        $this->assertSame('6124200773', $c->encrypt('0123456789'));
        $this->assertSame('0123456789', $c->decrypt('6124200773'));
    }

    public function testSample3(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3C'), self::hex('3737373770717273373737'), '0123456789abcdefghijklmnopqrstuvwxyz');
        $this->assertSame('a9tv40mll9kdu509eum', $c->encrypt('0123456789abcdefghi'));
        $this->assertSame('0123456789abcdefghi', $c->decrypt('a9tv40mll9kdu509eum'));
    }

    public function testSample4(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F'), '', '0123456789');
        $this->assertSame('2830668132', $c->encrypt('0123456789'));
        $this->assertSame('0123456789', $c->decrypt('2830668132'));
    }

    public function testSample5(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F'), self::hex('39383736353433323130'), '0123456789');
        $this->assertSame('2496655549', $c->encrypt('0123456789'));
        $this->assertSame('0123456789', $c->decrypt('2496655549'));
    }

    public function testSample6(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F'), self::hex('3737373770717273373737'), '0123456789abcdefghijklmnopqrstuvwxyz');
        $this->assertSame('xbj3kv35jrawxv32ysr', $c->encrypt('0123456789abcdefghi'));
        $this->assertSame('0123456789abcdefghi', $c->decrypt('xbj3kv35jrawxv32ysr'));
    }

    public function testSample7(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'), '', '0123456789');
        $this->assertSame('6657667009', $c->encrypt('0123456789'));
        $this->assertSame('0123456789', $c->decrypt('6657667009'));
    }

    public function testSample8(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'), self::hex('39383736353433323130'), '0123456789');
        $this->assertSame('1001623463', $c->encrypt('0123456789'));
        $this->assertSame('0123456789', $c->decrypt('1001623463'));
    }

    public function testSample9(): void
    {
        $c = new FF1(self::hex('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94'), self::hex('3737373770717273373737'), '0123456789abcdefghijklmnopqrstuvwxyz');
        $this->assertSame('xs8a0azh2avyalyzuwd', $c->encrypt('0123456789abcdefghi'));
        $this->assertSame('0123456789abcdefghi', $c->decrypt('xs8a0azh2avyalyzuwd'));
    }
}
