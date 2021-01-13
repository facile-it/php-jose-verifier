<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use Facile\JoseVerifier\Exception\InvalidTokenException;

/**
 * @psalm-import-type JWTPayloadObject from Psalm\PsalmTypes
 */
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
     * Verify OpenID token
     *
     * @param string $jwt
     *
     * @throws InvalidTokenException
     *
     * @return array The JWT Payload
     * @psalm-return JWTPayloadObject
     */
    public function verify(string $jwt): array;
}
