<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Facile\JoseVerifier\Internal\Checker\NonceChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;

class NonceCheckerTest extends TestCase
{
    public function testSupportedClaim(): void
    {
        $checker = new NonceChecker('foo');
        static::assertSame('nonce', $checker->supportedClaim());
    }

    public function testCheckClaim(): void
    {
        $checker = new NonceChecker('foo');
        $checker->checkClaim('foo');

        static::assertTrue(true);
    }

    public function testCheckClaimFail(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/Nonce mismatch/');

        $checker = new NonceChecker('foo');
        $checker->checkClaim('bar');
    }
}
