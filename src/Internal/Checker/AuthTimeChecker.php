<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Internal\Checker;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

use function is_int;
use function time;

/**
 * @internal
 */
final class AuthTimeChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'auth_time';

    private int $maxAge;

    private int $allowedTimeDrift;

    public function __construct(int $maxAge, int $allowedTimeDrift = 0)
    {
        $this->maxAge = $maxAge;
        $this->allowedTimeDrift = $allowedTimeDrift;
    }

    /**
     * @param mixed $value
     *
     * @throws InvalidClaimException
     */
    public function checkClaim($value): void
    {
        if (! is_int($value)) {
            throw new InvalidClaimException('"auth_time" must be an integer.', self::CLAIM_NAME, $value);
        }

        if ($value + $this->maxAge < time() - $this->allowedTimeDrift) {
            throw new InvalidClaimException('Too much time has elapsed since the last End-User authentication.', self::CLAIM_NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
