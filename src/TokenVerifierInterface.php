<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

interface TokenVerifierInterface
{
    public function withMaxAge(?int $maxAge): self;

    /**
     * Verify OpenID id_token
     *
     * @param string $jwt
     *
     * @return array The JWT Payload
     * @phpstan-return array<string, mixed>
     */
    public function verify(string $jwt): array;
}
