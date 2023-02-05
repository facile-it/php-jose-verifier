<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\JWK;

/**
 * @psalm-type JWKType = array{
 *     kty: "RSA"|"EC"|"oct"|string,
 *     use?: "sig"|"enc"|string,
 *     key_ops?: list<"sign"|"verify"|"encrypt"|"decrypt"|"wrapKey"|"unwrapKey"|"deriveKey"|"deriveBits"|string>,
 *     kid?: string,
 *     alg?: string,
 *     x5u?: string,
 *     x5c?: list<string>,
 *     x5t?: string,
 *     x5t#S256?: string,
 *     crv?: string,
 *     x?: string,
 *     y?: string,
 *     k?: string,
 *     n?: string,
 *     e?: string,
 *     d?: string,
 *     p?: string,
 *     q?: string,
 *     dp?: string,
 *     dq?: string,
 *     qi?: string
 * }
 * @psalm-type JWKSetType = array{keys: list<JWKType>}
 */
interface JwksProviderInterface
{
    /**
     * Get keys
     *
     * @psalm-return JWKSetType
     */
    public function getJwks(): array;

    /**
     * Require reload keys from source
     */
    public function reload(): static;
}
