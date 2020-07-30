<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use Facile\JoseVerifier\JWK\JwksProviderInterface;

/**
 * @phpstan-template TVerifier of TokenVerifierInterface
 */
interface TokenVerifierBuilderInterface
{
    /**
     * @param array<string, mixed> $clientMetadata
     */
    public function setClientMetadata(array $clientMetadata): void;

    /**
     * @param array<string, mixed> $issuerMetadata
     */
    public function setIssuerMetadata(array $issuerMetadata): void;

    public function setClockTolerance(int $clockTolerance): void;

    public function setAadIssValidation(bool $aadIssValidation): void;

    public function setJwksProvider(?JwksProviderInterface $jwksProvider): void;

    public function setClientJwksProvider(?JwksProviderInterface $clientJwksProvider): void;

    /**
     * @return TokenVerifierInterface
     * @phpstan-return TVerifier
     */
    public function build(): TokenVerifierInterface;
}
