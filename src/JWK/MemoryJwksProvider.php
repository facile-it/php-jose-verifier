<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\JWK;

class MemoryJwksProvider implements JwksProviderInterface
{
    /**
     * @var array
     * @phpstan-var array{keys: array<int, array<string, mixed>>}
     */
    private $jwks;

    /**
     * @param array $jwks
     * @phpstan-param array{keys: array<int, array<string, mixed>>} $jwks
     */
    public function __construct(array $jwks = ['keys' => []])
    {
        $this->jwks = $jwks;
    }

    /**
     * @inheritDoc
     */
    public function getJwks(): array
    {
        return $this->jwks;
    }

    /**
     * @inheritDoc
     */
    public function reload(): JwksProviderInterface
    {
        return $this;
    }
}
