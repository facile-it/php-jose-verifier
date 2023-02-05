<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Builder;

use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\TokenVerifierInterface;

/**
 * @psalm-api
 *
 * @psalm-import-type ClientMetadataType from TokenVerifierInterface
 * @psalm-import-type IssuerMetadataType from TokenVerifierInterface
 *
 * @template TVerifier of TokenVerifierInterface
 */
interface TokenVerifierBuilderInterface
{
    public function withClockTolerance(int $clockTolerance): TokenVerifierBuilderInterface;

    public function withAadIssValidation(bool $aadIssValidation): TokenVerifierBuilderInterface;

    public function withJwksProvider(JwksProviderInterface $jwksProvider): TokenVerifierBuilderInterface;

    public function withClientJwksProvider(JwksProviderInterface $clientJwksProvider): TokenVerifierBuilderInterface;

    /**
     * @psalm-return TVerifier
     */
    public function build(): TokenVerifierInterface;
}
