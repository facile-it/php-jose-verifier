<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\JWK;

interface JwksProviderInterface
{
    /**
     * Get keys
     *
     * @return array
     * @phpstan-return array{keys: array<int, array<string, mixed>>}
     */
    public function getJwks(): array;

    /**
     * Require reload keys from source
     *
     * @return $this
     */
    public function reload(): self;
}
