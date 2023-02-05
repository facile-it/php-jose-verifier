<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Builder;

use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Exception\InvalidArgumentException;
use Facile\JoseVerifier\IdTokenVerifier;
use Facile\JoseVerifier\TokenVerifierInterface;

/**
 * @psalm-api
 *
 * @psalm-type IssuerMetadataType = array{}&array{issuer: string, jwks_uri: string}
 *
 * @psalm-import-type ClientMetadataType from TokenVerifierInterface
 *
 * @template-extends AbstractTokenVerifierBuilder<IdTokenVerifier>
 */
final class IdTokenVerifierBuilder extends AbstractTokenVerifierBuilder
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
    protected function getVerifier(string $issuer, string $clientId): AbstractTokenVerifier
    {
        return new IdTokenVerifier($issuer, $clientId, $this->buildDecrypter());
    }

    protected function getExpectedAlg(): ?string
    {
        return $this->getClientMetadata()['id_token_signed_response_alg'] ?? null;
    }

    protected function getExpectedEncAlg(): ?string
    {
        return $this->getClientMetadata()['id_token_encrypted_response_alg'] ?? null;
    }

    protected function getExpectedEnc(): ?string
    {
        return $this->getClientMetadata()['id_token_encrypted_response_enc'] ?? null;
    }
}
