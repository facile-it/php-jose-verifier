<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Builder;

use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Decrypter\TokenDecrypter;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidArgumentException;
use Facile\JoseVerifier\JWK\JwksProviderBuilder;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\TokenVerifierInterface;

/**
 * @psalm-api
 *
 * @psalm-import-type JWKSetType from JwksProviderInterface
 * @psalm-import-type ClientMetadataType from TokenVerifierInterface
 *
 * @psalm-type IssuerMetadataType = array{}&array{issuer: string, jwks_uri: string}
 *
 * @template TVerifier of AbstractTokenVerifier
 *
 * @template-implements TokenVerifierBuilderInterface<TVerifier>
 */
abstract class AbstractTokenVerifierBuilder implements TokenVerifierBuilderInterface
{
    /**
     * @var array<string, mixed>
     *
     * @psalm-var ClientMetadataType
     */
    protected array $clientMetadata;

    /**
     * @var array<string, mixed>
     *
     * @psalm-var IssuerMetadataType
     */
    protected array $issuerMetadata;

    protected int $clockTolerance = 0;

    protected bool $aadIssValidation = false;

    protected ?JwksProviderInterface $clientJwksProvider = null;

    protected ?JwksProviderInterface $jwksProvider = null;

    protected ?JwksProviderBuilder $jwksProviderBuilder = null;

    /**
     * @psalm-param IssuerMetadataType $issuerMetadata
     * @psalm-param ClientMetadataType $clientMetadata
     */
    protected function __construct(array $issuerMetadata, array $clientMetadata)
    {
        $this->issuerMetadata = $issuerMetadata;
        $this->clientMetadata = $clientMetadata;
    }

    public function withClockTolerance(int $clockTolerance): static
    {
        $new = clone $this;
        $new->clockTolerance = $clockTolerance;

        return $new;
    }

    public function withAadIssValidation(bool $aadIssValidation): static
    {
        $new = clone $this;
        $new->aadIssValidation = $aadIssValidation;

        return $new;
    }

    public function withJwksProvider(JwksProviderInterface $jwksProvider): static
    {
        $new = clone $this;
        $new->jwksProvider = $jwksProvider;

        return $new;
    }

    public function withClientJwksProvider(JwksProviderInterface $clientJwksProvider): static
    {
        $new = clone $this;
        $new->clientJwksProvider = $clientJwksProvider;

        return $new;
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function buildJwksProvider(): JwksProviderInterface
    {
        $jwksUri = $this->getIssuerMetadata()['jwks_uri'] ?? null;

        $jwksBuilder = $this->jwksProviderBuilder ?? new JwksProviderBuilder();

        if (null !== $jwksUri) {
            $jwksBuilder = $jwksBuilder->withJwksUri($jwksUri);
        }

        return $jwksBuilder->build();
    }

    protected function buildClientJwksProvider(): JwksProviderInterface
    {
        /** @var JWKSetType $jwks */
        $jwks = ['keys' => []];

        $jwks = $this->clientMetadata['jwks'] ?? $jwks;

        return new MemoryJwksProvider($jwks);
    }

    public function withJwksProviderBuilder(?JwksProviderBuilder $jwksProviderBuilder): static
    {
        $new = clone $this;
        $new->jwksProviderBuilder = $jwksProviderBuilder;

        return $new;
    }

    /**
     * @psalm-return TVerifier
     */
    abstract protected function getVerifier(string $issuer, string $clientId): AbstractTokenVerifier;

    abstract protected function getExpectedAlg(): ?string;

    abstract protected function getExpectedEncAlg(): ?string;

    abstract protected function getExpectedEnc(): ?string;

    /**
     * @throws InvalidArgumentException
     *
     * @return array<string, mixed>
     *
     * @psalm-return ClientMetadataType
     */
    protected function getClientMetadata(): array
    {
        return $this->clientMetadata;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return array<string, mixed>
     *
     * @psalm-return IssuerMetadataType
     */
    protected function getIssuerMetadata(): array
    {
        return $this->issuerMetadata;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @psalm-return TVerifier
     */
    public function build(): TokenVerifierInterface
    {
        $issuer = $this->issuerMetadata['issuer'] ?? null;
        $clientId = $this->clientMetadata['client_id'] ?? null;

        if (empty($issuer)) {
            throw new InvalidArgumentException('Invalid "issuer" from issuer metadata');
        }

        if (empty($clientId)) {
            throw new InvalidArgumentException('Invalid "client_id" from client metadata');
        }

        $verifier = $this->getVerifier($issuer, $clientId)
            ->withJwksProvider($this->jwksProvider ?: $this->buildJwksProvider())
            ->withClientSecret($this->clientMetadata['client_secret'] ?? null)
            ->withAuthTimeRequired($this->clientMetadata['require_auth_time'] ?? false)
            ->withClockTolerance($this->clockTolerance)
            ->withAadIssValidation($this->aadIssValidation)
            ->withExpectedAlg($this->getExpectedAlg());

        return $verifier;
    }

    /**
     * @throws InvalidArgumentException On invalid id_token_encrypted* values
     */
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
            ->withClientSecret($this->getClientMetadata()['client_secret'] ?? null)
            ->withJwksProvider($this->clientJwksProvider ?: $this->buildClientJwksProvider());
    }
}
