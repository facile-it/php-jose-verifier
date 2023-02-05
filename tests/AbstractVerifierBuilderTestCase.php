<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Facile\JoseVerifier\Builder\AbstractTokenVerifierBuilder;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\JWK\RemoteJwksProvider;
use function get_class;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

abstract class AbstractVerifierBuilderTestCase extends TestCase
{
    abstract protected function getBuilder(array $issuerMetadata, array $clientMetadata): AbstractTokenVerifierBuilder;

    abstract protected function getExpectedVerifierClass(): string;

    /**
     * @return mixed
     */
    protected function getPropertyValue(object $instance, string $propertyName)
    {
        $reflectionClass = new ReflectionClass(get_class($instance));
        $property = $reflectionClass->getProperty($propertyName);
        $property->setAccessible(true);

        return $property->getValue($instance);
    }

    public function testShouldBuildWithMinimalInfo(): void
    {
        $issuerMetadata = [
            'issuer' => 'https://issuer',
        ];
        $clientMetadata = [
            'client_id' => 'client-id',
        ];

        $builder = $this->getBuilder($issuerMetadata, $clientMetadata);

        $verifier = $builder->build();

        $this->assertInstanceOf($this->getExpectedVerifierClass(), $verifier);
        $this->assertSame('client-id', $this->getPropertyValue($verifier, 'clientId'));
        $this->assertSame('https://issuer', $this->getPropertyValue($verifier, 'issuer'));

        /** @var JwksProviderInterface $jwksProvider */
        $jwksProvider = $this->getPropertyValue($verifier, 'jwksProvider');
        $this->assertInstanceOf(MemoryJwksProvider::class, $jwksProvider);
        $this->assertSame(['keys' => []], $jwksProvider->getJwks());
    }

    public function testShouldBuildWithProvidedJwks(): void
    {
        $issuerJwks = ['keys' => [['foo' => 'bar']]];
        $issuerMetadata = [
            'issuer' => 'https://issuer',
        ];
        $clientMetadata = [
            'client_id' => 'client-id',
            'jwks' => $issuerJwks,
        ];

        $builder = $this->getBuilder($issuerMetadata, $clientMetadata)
            ->withJwksProvider(new MemoryJwksProvider($issuerJwks));

        $verifier = $builder->build();

        $this->assertInstanceOf($this->getExpectedVerifierClass(), $verifier);
        $this->assertSame('client-id', $this->getPropertyValue($verifier, 'clientId'));
        $this->assertSame('https://issuer', $this->getPropertyValue($verifier, 'issuer'));
        $this->assertNull($this->getPropertyValue($verifier, 'expectedAlg'));

        /** @var JwksProviderInterface $jwksProvider */
        $jwksProvider = $this->getPropertyValue($verifier, 'jwksProvider');
        $this->assertInstanceOf(MemoryJwksProvider::class, $jwksProvider);
        $this->assertSame($issuerJwks, $jwksProvider->getJwks());
    }

    public function testShouldBuildWithCompleteInfo(): void
    {
        $issuerJwks = ['keys' => [['foo' => 'bar']]];
        $issuerMetadata = [
            'issuer' => 'https://issuer',
            'jwks_uri' => 'https://jwks_uri',
        ];
        $clientMetadata = [
            'client_id' => 'client-id',
            'client_secret' => 'foo',
            'require_auth_time' => true,
            'jwks' => $issuerJwks,
        ];

        $builder = $this->getBuilder($issuerMetadata, $clientMetadata)
            ->withClockTolerance(6)
            ->withAadIssValidation(true);

        $verifier = $builder->build();

        $this->assertInstanceOf($this->getExpectedVerifierClass(), $verifier);
        $this->assertSame('client-id', $this->getPropertyValue($verifier, 'clientId'));
        $this->assertSame('https://issuer', $this->getPropertyValue($verifier, 'issuer'));
        $this->assertSame('foo', $this->getPropertyValue($verifier, 'clientSecret'));
        $this->assertTrue($this->getPropertyValue($verifier, 'authTimeRequired'));
        $this->assertSame(6, $this->getPropertyValue($verifier, 'clockTolerance'));
        $this->assertTrue($this->getPropertyValue($verifier, 'aadIssValidation'));

        /** @var JwksProviderInterface $jwksProvider */
        $jwksProvider = $this->getPropertyValue($verifier, 'jwksProvider');
        $this->assertInstanceOf(RemoteJwksProvider::class, $jwksProvider);
        $this->assertSame('https://jwks_uri', $this->getPropertyValue($jwksProvider, 'uri'));
    }
}
