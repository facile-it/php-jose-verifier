<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;
use function sprintf;

abstract class AbstractHashCheckerTest extends TestCase
{
    protected const FOO_HASH_512 = '9_u6bgY2-JDlb7vzKD5STG-jIErimDgtYkdB0NxmODI';

    protected const FOO_HASH_384 = 'mMEf_f3VQGdrGhN8saIrKnA1DJpEFx1r';

    protected const FOO_HASH_256 = 'LCa0a2j_xo_5m0U8HTBBNA';

    abstract protected function getSupportedClaim(): string;

    abstract protected function getChecker(string $alg): ClaimChecker;

    public function testSupportedClaim(): void
    {
        static::assertSame($this->getSupportedClaim(), $this->getChecker('RS256')->supportedClaim());
    }

    public function testCheckClaimWith512(): void
    {
        $this->getChecker('RS512')->checkClaim(static::FOO_HASH_512);

        static::assertTrue(true);
    }

    public function testCheckClaimWith384(): void
    {
        $this->getChecker('RS384')->checkClaim(static::FOO_HASH_384);

        static::assertTrue(true);
    }

    public function testCheckClaimWith256(): void
    {
        $this->getChecker('RS256')->checkClaim(static::FOO_HASH_256);

        static::assertTrue(true);
    }

    public function testCheckClaimWithWrongValue(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches(sprintf('/%s mismatch/', $this->getSupportedClaim()));
        $this->getChecker('RS256')->checkClaim('bar');

        static::assertTrue(true);
    }
}
