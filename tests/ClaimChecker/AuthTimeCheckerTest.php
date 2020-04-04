<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest\ClaimChecker;

use Facile\JoseVerifier\ClaimChecker\AuthTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;
use function time;

class AuthTimeCheckerTest extends TestCase
{
    public function testSupportedClaim(): void
    {
        $checker = new AuthTimeChecker(1);
        static::assertSame('auth_time', $checker->supportedClaim());
    }

    public function testCheckClaim(): void
    {
        $checker = new AuthTimeChecker(1);

        $checker->checkClaim(time());

        static::assertTrue(true);
    }

    public function testCheckClaimTooOld(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/Too much time has elapsed since the last End-User authentication/');

        $checker = new AuthTimeChecker(1);

        $checker->checkClaim(time() - 2);
    }

    public function testCheckClaimTooOldButWithTolerance(): void
    {
        $checker = new AuthTimeChecker(1, 2);

        $checker->checkClaim(time() - 2);

        static::assertTrue(true);
    }

    public function testCheckClaimWithNotIntValue(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/"auth_time" must be an integer/');

        $checker = new AuthTimeChecker(1);

        $checker->checkClaim('345');
    }
}
