<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Facile\JoseVerifier\Internal\Checker\CHashChecker;
use Jose\Component\Checker\ClaimChecker;

class CHashCheckerTestCase extends AbstractHashCheckerTestCase
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
