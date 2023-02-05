<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Facile\JoseVerifier\Builder\AbstractTokenVerifierBuilder;
use Facile\JoseVerifier\Builder\IdTokenVerifierBuilder;
use Facile\JoseVerifier\IdTokenVerifier;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\JWK\RemoteJwksProvider;

class IdTokenVerifierBuilderTest extends AbstractVerifierBuilderTestCase
{
    protected function getBuilder(array $issuerMetadata, array $clientMetadata): AbstractTokenVerifierBuilder
    {
        return IdTokenVerifierBuilder::create($issuerMetadata, $clientMetadata);
    }

    protected function getExpectedVerifierClass(): string
    {
        return IdTokenVerifier::class;
    }

    public function testShouldInjectExpectedAlg(): void
    {
        $issuerMetadata = [
            'issuer' => 'https://issuer',
        ];
        $clientMetadata = [
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'id_token_signed_response_alg' => 'sigAlg',
        ];

        $builder = $this->getBuilder($issuerMetadata, $clientMetadata);

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
            'id_token_signed_response_alg' => 'sigAlg',
            'id_token_encrypted_response_alg' => 'encAlg',
            'id_token_encrypted_response_enc' => 'encEnc',
            'jwks' => $clientJwks,
        ];

        $builder = $this->getBuilder($issuerMetadata, $clientMetadata);

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
