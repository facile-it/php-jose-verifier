<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\JWK;

/**
 * @psalm-import-type JWKSetType from JwksProviderInterface
 */
final class MemoryJwksProvider implements JwksProviderInterface
{
    /** @psalm-var JWKSetType */
    private array $jwks;

    /**
     * @psalm-param JWKSetType $jwks
     */
    public function __construct(array $jwks = ['keys' => []])
    {
        $this->jwks = $jwks;
    }

    public function getJwks(): array
    {
        return $this->jwks;
    }

    public function reload(): static
    {
        return $this;
    }
}
