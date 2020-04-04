<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest\ClaimChecker;

use Facile\JoseVerifier\ClaimChecker\CHashChecker;
use Jose\Component\Checker\ClaimChecker;

class CHashCheckerTest extends AbstractHashCheckerTest
{
    protected function getSupportedClaim(): string
    {
        return 'c_hash';
    }

    protected function getChecker(string $alg): ClaimChecker
    {
        return new CHashChecker('foo', $alg);
    }
}
