<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

/**
 * @psalm-api
 */
interface IdTokenVerifierInterface extends TokenVerifierInterface
{
    public function withAccessToken(?string $accessToken): static;

    public function withCode(?string $code): static;

    public function withState(?string $state): static;
}
