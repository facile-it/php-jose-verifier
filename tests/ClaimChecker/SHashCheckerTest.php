<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Facile\JoseVerifier\Internal\Checker\SHashChecker;
use Jose\Component\Checker\ClaimChecker;

class SHashCheckerTest extends AbstractHashCheckerTest
{
    protected function getSupportedClaim(): string
    {
        return 's_hash';
    }

    protected function getChecker(string $alg): ClaimChecker
    {
        return new SHashChecker('foo', $alg);
    }
}
