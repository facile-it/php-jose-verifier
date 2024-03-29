<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Internal\Checker;

/**
 * @internal
 */
final class CHashChecker extends AbstractHashChecker
{
    private const CLAIM_NAME = 'c_hash';

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
