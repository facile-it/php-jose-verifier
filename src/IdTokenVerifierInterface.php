<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

interface IdTokenVerifierInterface extends TokenVerifierInterface
{
    public function withAccessToken(?string $accessToken): self;

    public function withCode(?string $code): self;

    public function withState(?string $state): self;
}
