<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Builder;

use Facile\JoseVerifier\Exception\InvalidArgumentException;
use Facile\JoseVerifier\JWTVerifier;
use Facile\JoseVerifier\TokenVerifierInterface;

/**
 * @psalm-api
 * @psalm-type IssuerMetadataType = array{}&array{issuer: string, jwks_uri: string}
 * @psalm-import-type ClientMetadataType from TokenVerifierInterface
 *
 * @template-extends AbstractTokenVerifierBuilder<JWTVerifier>
 */
final class AccessTokenVerifierBuilder extends AbstractTokenVerifierBuilder
{
    /**
     * @psalm-param IssuerMetadataType $issuerMetadata
     * @psalm-param ClientMetadataType $clientMetadata
     */
    public static function create(array $issuerMetadata, array $clientMetadata): static
    {
        return new self($issuerMetadata, $clientMetadata);
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function getVerifier(string $issuer, string $clientId): JWTVerifier
    {
        return new JWTVerifier($issuer, $clientId, $this->buildDecrypter());
    }

    protected function getExpectedAlg(): ?string
    {
        return null;
    }

    protected function getExpectedEncAlg(): ?string
    {
        return null;
    }

    protected function getExpectedEnc(): ?string
    {
        return null;
    }
}
