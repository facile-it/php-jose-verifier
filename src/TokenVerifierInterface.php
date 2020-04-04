<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

interface TokenVerifierInterface
{
    /**
     * @param string|null $nonce
     *
     * @return $this
     */
    public function withNonce(?string $nonce);

    /**
     * @param int|null $maxAge
     *
     * @return $this
     */
    public function withMaxAge(?int $maxAge);

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
