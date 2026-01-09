<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Facile\JoseVerifier\Internal\InternalClock;
use Facile\JoseVerifier\Internal\Checker\AuthTimeChecker;
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

    public function testCheckClaimWithoutClock(): void
    {
        $this->expectNotToPerformAssertions();
        $checker = new AuthTimeChecker(1);

        $checker->checkClaim(time());
    }

    public function testCheckClaim(): void
    {
        $this->expectNotToPerformAssertions();
        $clock = new InternalClock(new \DateTimeImmutable('2026-01-08 17:00:00'));
        $checker = new AuthTimeChecker(0, 0, $clock);

        $checker->checkClaim($clock->now()->getTimestamp());
    }

    public function testCheckClaimTooOld(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/Too much time has elapsed since the last End-User authentication/');

        $clock = new InternalClock(new \DateTimeImmutable('2026-01-08 17:00:00'));
        $checker = new AuthTimeChecker(0, 0, $clock);

        $checker->checkClaim($clock->now()->getTimestamp() - 1);
    }

    public function testCheckClaimTooOldButWithTolerance(): void
    {
        $clock = new InternalClock(new \DateTimeImmutable('2026-01-08 17:00:00'));
        $checker = new AuthTimeChecker(1, 2, $clock);

        $checker->checkClaim($clock->now()->getTimestamp() - 2);

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
