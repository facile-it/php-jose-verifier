<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest\ClaimChecker;

use Facile\JoseVerifier\ClaimChecker\AtHashChecker;
use Jose\Component\Checker\ClaimChecker;

class AtHashCheckerTest extends AbstractHashCheckerTest
{
    protected function getSupportedClaim(): string
    {
        return 'at_hash';
    }

    protected function getChecker(string $alg): ClaimChecker
    {
        return new AtHashChecker('foo', $alg);
    }
}
