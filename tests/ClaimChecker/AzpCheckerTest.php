<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest\ClaimChecker;

use Facile\JoseVerifier\ClaimChecker\AzpChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;

class AzpCheckerTest extends TestCase
{
    public function testSupportedClaim(): void
    {
        $checker = new AzpChecker('foo');
        static::assertSame('azp', $checker->supportedClaim());
    }

    public function testCheckClaim(): void
    {
        $checker = new AzpChecker('foo');
        $checker->checkClaim('foo');

        static::assertTrue(true);
    }

    public function testCheckClaimFail(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/azp must be the client_id/');

        $checker = new AzpChecker('foo');
        $checker->checkClaim('bar');
    }
}
