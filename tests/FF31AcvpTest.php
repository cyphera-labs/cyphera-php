<?php

declare(strict_types=1);

namespace Cyphera\Tests;

use Cyphera\FF31;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** FF3-1 conformance — all 18 NIST ACVP AES-FF3-1 test vectors (56-bit tweaks). */
class FF31AcvpTest extends TestCase
{
    private const A26 = 'abcdefghijklmnopqrstuvwxyz';
    private const A64 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/';
    private const D = '0123456789';

    /** @return array<int, array{0:string,1:string,2:string,3:string,4:string}> */
    public static function acvpVectors(): array
    {
        return [
            ['2DE79D232DF5585D68CE47882AE256D6', 'CBD09280979564', self::D, '3992520240', '8901801106'],
            ['01C63017111438F7FC8E24EB16C71AB5', 'C4E822DCD09F27', self::D, '60761757463116869318437658042297305934914824457484538562', '35637144092473838892796702739628394376915177448290847293'],
            ['718385E6542534604419E83CE387A437', 'B6F35084FA90E1', self::A26, 'wfmwlrorcd', 'ywowehycyd'],
            ['DB602DFF22ED7E84C8D8C865A941A238', 'EBEFD63BCC2083', self::A26, 'kkuomenbzqvggfbteqdyanwpmhzdmoicekiihkrm', 'belcfahcwwytwrckieymthabgjjfkxtxauipmjja'],
            ['AEE87D0D485B3AFD12BD1E0B9D03D50D', '5F9140601D224B', self::A64, 'ixvuuIHr0e', 'GR90R1q838'],
            ['7B6C88324732F7F4AD435DA9AD77F917', '3F42102C0BAB39', self::A64, '21q1kbbIVSrAFtdFWzdMeIDpRqpo', 'cvQ/4aGUV4wRnyO3CHmgEKW5hk8H'],
            ['F62EDB777A671075D47563F3A1E9AC797AA706A2D8E02FC8', '493B8451BF6716', self::D, '4406616808', '1807744762'],
            ['0951B475D1A327C52756F2624AF224C80E9BE85F09B2D44F', 'D679E2EA3054E1', self::D, '99980459818278359406199791971849884432821321826358606310', '84359031857952748660483617398396641079558152339419110919'],
            ['49CCB8F62D941E5684599ECA0300937B5C766D053E109777', '0BFCF75CDC2FC1', self::A26, 'jaxlrchjjx', 'kjdbfqyahd'],
            ['03D253674A9309FF07ED0E71B24CBFE769025E09FCE544D7', 'B33176B1DA0F6C', self::A26, 'tafzrybuvhiqvcyztuxfnwfprmqlwpayphxbawpl', 'loaemzbgqkywkdhmncrijzildzleoqibtthdiliv'],
            ['1C24B74B7C1B9969314CB53E92F98EFD620D5520017FB076', '0380341C425A6F', self::A64, '6np8r2t8zo', 'HgpCXoA1Rt'],
            ['C0ABADFC071379824A070E8C3FD40DD9BFD7A3C99A0D5FE3', '6C2926C705DDAF', self::A64, 'GKB6sa9g56BSJ09iJ4dsaxRdsMvo', 'gC0tTSdDPxM79QOWi+z+SNL9C4V+'],
            ['1FAA03EFF55A06F8FAB3F1DC57127D493E2F8F5C365540467A3A055BDBE6481D', '4D67130C030445', self::D, '3679409436', '1735794859'],
            ['9CE16E125BD422A011408EB083355E7089E70A4CD2F59E141D0B94A74BCC5967', '4684635BD2C821', self::D, '85783290820098255530464619643265070052870796363685134012', '75104723514036464144839960480545848044718729603261409917'],
            ['6187F8BDE99F7DAF9E3EE8A8654308E7E51D31FA88AFFAEB5592041C033B736B', '5820812B3D5DD1', self::A26, 'mkblaoiyfd', 'ifpyiihvvq'],
            ['F6807FB9688937E4D4956006C8F0CB2394148A5F4B14666CF353F4941428FFD7', '30C87B99890096', self::A26, 'wrammvhudopmaazlsxevzwzwpezzmghwfnmkitnk', 'nzftnfkliuctlmtdfrxfhwgevrbcbgljurnytxkj'],
            ['9C2B69F7DDF181C54398E345BE04C2F6B00B9DD1679200E1E04C4FF961AE0F09', '103C238B4B1E44', self::A64, 'H2/c6FblSA', 'EOg4H1bE+8'],
            ['C58BCBD08B90006CEC7E82B2D987D79F6A21111DEF0CEBB273CBAEB2D6CD4044', '7036604882667B', self::A64, 'bz5TcS1krnD8IOLdrQeKzXkLAa6h', 'Z6x3/9LPW8SZunRezRM8J68Q4J03'],
        ];
    }

    #[DataProvider('acvpVectors')]
    public function testAcvpVector(string $key, string $tweak, string $alphabet, string $pt, string $ct): void
    {
        $cipher = new FF31(hex2bin($key), hex2bin($tweak), $alphabet);
        $this->assertSame($ct, $cipher->encrypt($pt), 'FF3-1 encrypt');
        $this->assertSame($pt, $cipher->decrypt($ct), 'FF3-1 decrypt');
    }

    public function testRejectsEightByteTweak(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new FF31(hex2bin('2DE79D232DF5585D68CE47882AE256D6'), str_repeat("\x00", 8), self::D);
    }
}
