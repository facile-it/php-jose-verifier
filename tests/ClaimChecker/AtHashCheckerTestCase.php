<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\ClaimChecker;

use Facile\JoseVerifier\Internal\Checker\AtHashChecker;
use Jose\Component\Checker\ClaimChecker;

class AtHashCheckerTestCase extends AbstractHashCheckerTestCase
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
