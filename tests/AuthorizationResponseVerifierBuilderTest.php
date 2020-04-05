<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest;

use Facile\JoseVerifier\AbstractTokenVerifierBuilder;
use Facile\JoseVerifier\AuthorizationResponseVerifierBuilder;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\JWK\RemoteJwksProvider;
use Facile\JoseVerifier\JWTVerifier;

class AuthorizationResponseVerifierBuilderTest extends AbstractVerifierBuilderTestCase
{
    protected function getBuilder(): AbstractTokenVerifierBuilder
    {
        return new AuthorizationResponseVerifierBuilder();
    }

    protected function getExpectedVerifierClass(): string
    {
        return JWTVerifier::class;
    }

    public function testShouldInjectExpectedAlg(): void
    {
        $issuerMetadata = [
            'issuer' => 'https://issuer',
        ];
        $clientMetadata = [
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'authorization_signed_response_alg' => 'sigAlg',
        ];

        $builder = $this->getBuilder();
        $builder->setIssuerMetadata($issuerMetadata);
        $builder->setClientMetadata($clientMetadata);

        $verifier = $builder->build();

        $this->assertSame('sigAlg', $this->getPropertyValue($verifier, 'expectedAlg'));
    }

    public function testShouldInjectDecrypter(): void
    {
        $clientJwks = [
            'keys' => [
                ['foo' => 'bar'],
            ],
        ];
        $issuerMetadata = [
            'issuer' => 'https://issuer',
            'jwks_uri' => 'https://jwks_uri',
        ];
        $clientMetadata = [
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'authorization_signed_response_alg' => 'sigAlg',
            'authorization_encrypted_response_alg' => 'encAlg',
            'authorization_encrypted_response_enc' => 'encEnc',
            'jwks' => $clientJwks,
        ];

        $builder = $this->getBuilder();
        $builder->setIssuerMetadata($issuerMetadata);
        $builder->setClientMetadata($clientMetadata);

        $verifier = $builder->build();

        $this->assertInstanceOf($this->getExpectedVerifierClass(), $verifier);

        /** @var \Facile\JoseVerifier\Decrypter\TokenDecrypterInterface $decrypter */
        $decrypter = $this->getPropertyValue($verifier, 'decrypter');
        $this->assertInstanceOf(\Facile\JoseVerifier\Decrypter\TokenDecrypterInterface::class, $decrypter);

        $this->assertSame('encAlg', $this->getPropertyValue($decrypter, 'expectedAlg'));
        $this->assertSame('encEnc', $this->getPropertyValue($decrypter, 'expectedEnc'));
        $this->assertSame('client-secret', $this->getPropertyValue($decrypter, 'clientSecret'));
        /** @var JwksProviderInterface $clientJwksProvider */
        $clientJwksProvider = $this->getPropertyValue($decrypter, 'jwksProvider');
        $this->assertInstanceOf(MemoryJwksProvider::class, $clientJwksProvider);
        $this->assertSame($clientJwks, $clientJwksProvider->getJwks());

        $this->assertSame('client-id', $this->getPropertyValue($verifier, 'clientId'));
        $this->assertSame('https://issuer', $this->getPropertyValue($verifier, 'issuer'));
        $this->assertSame('sigAlg', $this->getPropertyValue($verifier, 'expectedAlg'));

        /** @var JwksProviderInterface $jwksProvider */
        $jwksProvider = $this->getPropertyValue($verifier, 'jwksProvider');
        $this->assertInstanceOf(RemoteJwksProvider::class, $jwksProvider);
        $this->assertSame('https://jwks_uri', $this->getPropertyValue($jwksProvider, 'uri'));
    }
}
