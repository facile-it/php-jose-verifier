<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;

/**
 * @phpstan-extends AbstractTokenVerifierBuilder<UserInfoVerifier>
 */
final class UserInfoVerifierBuilder extends AbstractTokenVerifierBuilder
{
    protected function getVerifier(string $issuer, string $clientId, ?TokenDecrypterInterface $decrypter = null): AbstractTokenVerifier
    {
        return new UserInfoVerifier($issuer, $clientId, $this->buildDecrypter());
    }

    protected function getExpectedAlg(): ?string
    {
        return $this->clientMetadata['userinfo_signed_response_alg'] ?? null;
    }

    protected function getExpectedEncAlg(): ?string
    {
        return $this->clientMetadata['userinfo_encrypted_response_alg'] ?? null;
    }

    protected function getExpectedEnc(): ?string
    {
        return $this->clientMetadata['userinfo_encrypted_response_enc'] ?? null;
    }
}
