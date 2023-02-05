<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Builder;

use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidArgumentException;
use Facile\JoseVerifier\TokenVerifierInterface;
use Facile\JoseVerifier\UserInfoVerifier;

/**
 * @psalm-api
 * @psalm-type IssuerMetadataType = array{}&array{issuer: string, jwks_uri: string}
 * @psalm-import-type ClientMetadataType from TokenVerifierInterface
 *
 * @template-extends AbstractTokenVerifierBuilder<UserInfoVerifier>
 */
final class UserInfoVerifierBuilder extends AbstractTokenVerifierBuilder
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
    protected function getVerifier(string $issuer, string $clientId, ?TokenDecrypterInterface $decrypter = null): AbstractTokenVerifier
    {
        return new UserInfoVerifier($issuer, $clientId, $this->buildDecrypter());
    }

    protected function getExpectedAlg(): ?string
    {
        return $this->getClientMetadata()['userinfo_signed_response_alg'] ?? null;
    }

    protected function getExpectedEncAlg(): ?string
    {
        return $this->getClientMetadata()['userinfo_encrypted_response_alg'] ?? null;
    }

    protected function getExpectedEnc(): ?string
    {
        return $this->getClientMetadata()['userinfo_encrypted_response_enc'] ?? null;
    }
}
