<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use Facile\JoseVerifier\Decrypter\TokenDecrypter;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidArgumentException;
use Facile\JoseVerifier\JWK\JwksProviderBuilder;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;

/**
 * @phpstan-template TVerifier of AbstractTokenVerifier
 * @phpstan-implements TokenVerifierBuilderInterface<TVerifier>
 */
abstract class AbstractTokenVerifierBuilder implements TokenVerifierBuilderInterface
{
    /** @var array<string, mixed> */
    protected $clientMetadata = [];

    /** @var array<string, mixed> */
    protected $issuerMetadata = [];

    /** @var int */
    protected $clockTolerance = 0;

    /** @var bool */
    protected $aadIssValidation = false;

    /** @var JwksProviderInterface|null */
    protected $clientJwksProvider;

    /** @var JwksProviderInterface|null */
    protected $jwksProvider;

    /** @var JwksProviderBuilder|null */
    protected $jwksProviderBuilder;

    /**
     * @param array<string, mixed> $clientMetadata
     */
    public function setClientMetadata(array $clientMetadata): void
    {
        $this->clientMetadata = $clientMetadata;
    }

    /**
     * @param array<string, mixed> $issuerMetadata
     */
    public function setIssuerMetadata(array $issuerMetadata): void
    {
        $this->issuerMetadata = $issuerMetadata;
    }

    public function setClockTolerance(int $clockTolerance): void
    {
        $this->clockTolerance = $clockTolerance;
    }

    public function setAadIssValidation(bool $aadIssValidation): void
    {
        $this->aadIssValidation = $aadIssValidation;
    }

    public function setJwksProvider(?JwksProviderInterface $jwksProvider): void
    {
        $this->jwksProvider = $jwksProvider;
    }

    public function setClientJwksProvider(?JwksProviderInterface $clientJwksProvider): void
    {
        $this->clientJwksProvider = $clientJwksProvider;
    }

    protected function buildJwksProvider(): JwksProviderInterface
    {
        if (null !== $this->jwksProvider) {
            return $this->jwksProvider;
        }

        /** @var string|null $jwksUri */
        $jwksUri = $this->issuerMetadata['jwks_uri'] ?? null;

        $jwksBuilder = $this->jwksProviderBuilder ?? new JwksProviderBuilder();
        $jwksBuilder->setJwksUri($jwksUri);

        return $jwksBuilder->build();
    }

    protected function buildClientJwksProvider(): JwksProviderInterface
    {
        if (null !== $this->clientJwksProvider) {
            return $this->clientJwksProvider;
        }

        /** @var array{keys: array<int, array<string, mixed>>} $jwks */
        $jwks = $this->clientMetadata['jwks'] ?? null;

        return new MemoryJwksProvider($jwks ?? ['keys' => []]);
    }

    public function setJwksProviderBuilder(?JwksProviderBuilder $jwksProviderBuilder): void
    {
        $this->jwksProviderBuilder = $jwksProviderBuilder;
    }

    /**
     * @param string $issuer
     * @param string $clientId
     *
     * @return AbstractTokenVerifier
     * @phpstan-return TVerifier
     */
    abstract protected function getVerifier(string $issuer, string $clientId): AbstractTokenVerifier;

    abstract protected function getExpectedAlg(): ?string;

    abstract protected function getExpectedEncAlg(): ?string;

    abstract protected function getExpectedEnc(): ?string;

    /**
     * @return TokenVerifierInterface
     * @phpstan-return TVerifier
     */
    public function build(): TokenVerifierInterface
    {
        /** @var string|null $issuer */
        $issuer = $this->issuerMetadata['issuer'] ?? null;
        /** @var string|null $clientId */
        $clientId = $this->clientMetadata['client_id'] ?? null;

        if (null === $issuer) {
            throw new InvalidArgumentException('Unable to get issuer from issuer metadata');
        }

        if (null === $clientId) {
            throw new InvalidArgumentException('Unable to get client_id from client metadata');
        }

        $verifier = $this->getVerifier($issuer, $clientId)
            ->withJwksProvider($this->buildJwksProvider())
            ->withClientSecret($this->clientMetadata['client_secret'] ?? null)
            ->withAuthTimeRequired($this->clientMetadata['require_auth_time'] ?? false)
            ->withClockTolerance($this->clockTolerance)
            ->withAadIssValidation($this->aadIssValidation)
            ->withExpectedAlg($this->getExpectedAlg());

        return $verifier;
    }

    protected function buildDecrypter(): ?TokenDecrypterInterface
    {
        $alg = $this->getExpectedEncAlg();
        $enc = $this->getExpectedEnc();

        if ((null !== $alg) xor (null !== $enc)) {
            throw new InvalidArgumentException('Invalid values received for id_token_encrypted* values');
        }

        if (null === $alg) {
            return null;
        }

        return (new TokenDecrypter())
            ->withExpectedAlg($alg)
            ->withExpectedEnc($enc)
            ->withClientSecret($this->clientMetadata['client_secret'] ?? null)
            ->withJwksProvider($this->buildClientJwksProvider());
    }
}
