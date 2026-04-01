<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use PHPUnit\Framework\TestCase;

class CallableCheckerTest extends TestCase
{
    public function testSupportedClaim(): void
    {
        $checker = new CallableChecker('foo', static fn(): true => true);
        self::assertSame('foo', $checker->supportedClaim());
    }

    public function testSupportedHeader(): void
    {
        $checker = new CallableChecker('foo', static fn(): true => true);
        self::assertSame('foo', $checker->supportedHeader());
    }

    public function testProtectedHeaderOnly(): void
    {
        $checker = new CallableChecker('foo', static fn(): true => true);
        self::assertTrue($checker->protectedHeaderOnly());
    }

    public function testCheckClaim(): void
    {
        $checker = new CallableChecker('foo', static fn($value): bool => $value === 'foo');
        $checker->checkClaim('foo');

        self::assertTrue(true);
    }

    public function testCheckClaimFail(): void
    {
        $this->expectException(InvalidClaimException::class);

        $checker = new CallableChecker('foo', static fn($value): bool => $value === 'foo');
        $checker->checkClaim('bar');
    }

    public function testCheckHeader(): void
    {
        $checker = new CallableChecker('foo', static fn($value): bool => $value === 'foo');
        $checker->checkHeader('foo');

        self::assertTrue(true);
    }

    public function testCheckHeaderFail(): void
    {
        $this->expectException(InvalidHeaderException::class);

        $checker = new CallableChecker('foo', static fn($value): bool => $value === 'foo');
        $checker->checkHeader('bar');
    }
}
