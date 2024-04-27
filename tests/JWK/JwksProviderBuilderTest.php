<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\JWK;

use Facile\JoseVerifier\JWK\CachedJwksProvider;
use Facile\JoseVerifier\JWK\JwksProviderBuilder;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\JWK\RemoteJwksProvider;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use ReflectionClass;

use function get_class;

class JwksProviderBuilderTest extends TestCase
{
    use ProphecyTrait;

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

    public function testShouldCreateEmptyProviderWithoutParams(): void
    {
        $builder = new JwksProviderBuilder();
        $provider = $builder->build();

        $this->assertInstanceOf(MemoryJwksProvider::class, $provider);
        $this->assertCount(0, $provider->getJwks()['keys']);
    }

    public function testShouldCreateStaticProviderWithJwks(): void
    {
        $jwks = ['keys' => [
            ['kid' => 'foo'],
        ]];
        $builder = new JwksProviderBuilder();
        $provider = $builder->withJwks($jwks)->build();

        $this->assertInstanceOf(MemoryJwksProvider::class, $provider);
        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testShouldCreateRemoteProviderWithJwksUri(): void
    {
        $builder = new JwksProviderBuilder();

        $provider = $builder->withJwksUri('https://jwks_uri')->build();

        $this->assertInstanceOf(RemoteJwksProvider::class, $provider);
        $this->assertSame('https://jwks_uri', $this->getPropertyValue($provider, 'uri'));
    }

    public function testShouldCreateRemoteProviderWithCustomDeps(): void
    {
        $httpClient = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);

        $builder = new JwksProviderBuilder();
        $builder = $builder->withJwksUri('https://jwks_uri');
        $builder = $builder->withHttpClient($httpClient->reveal());
        $builder = $builder->withRequestFactory($requestFactory->reveal());

        $provider = $builder->build();

        $this->assertInstanceOf(RemoteJwksProvider::class, $provider);
        $this->assertSame('https://jwks_uri', $this->getPropertyValue($provider, 'uri'));
        $this->assertSame($httpClient->reveal(), $this->getPropertyValue($provider, 'client'));
        $this->assertSame($requestFactory->reveal(), $this->getPropertyValue($provider, 'requestFactory'));
    }

    public function testShouldCreateRemoteProviderWithCache(): void
    {
        $cache = $this->prophesize(CacheInterface::class);

        $builder = new JwksProviderBuilder();
        $builder = $builder->withJwksUri('https://jwks_uri');
        $builder = $builder->withCache($cache->reveal());

        $provider = $builder->build();

        $this->assertInstanceOf(CachedJwksProvider::class, $provider);
        $this->assertSame($cache->reveal(), $this->getPropertyValue($provider, 'cache'));
        $this->assertSame(86_400, $this->getPropertyValue($provider, 'ttl'));

        /** @var RemoteJwksProvider $remoteProvider */
        $remoteProvider = $this->getPropertyValue($provider, 'provider');

        $this->assertInstanceOf(RemoteJwksProvider::class, $remoteProvider);
        $this->assertSame('https://jwks_uri', $this->getPropertyValue($remoteProvider, 'uri'));
    }

    /**
     * @depends testShouldCreateRemoteProviderWithCache
     */
    public function testShouldCreateRemoteProviderWithCacheTtl(): void
    {
        $cache = $this->prophesize(CacheInterface::class);

        $builder = new JwksProviderBuilder();
        $builder = $builder->withJwksUri('https://jwks_uri');
        $builder = $builder->withCache($cache->reveal());
        $builder = $builder->withCacheTtl(5);

        $provider = $builder->build();

        $this->assertInstanceOf(CachedJwksProvider::class, $provider);
        $this->assertSame(5, $this->getPropertyValue($provider, 'ttl'));
    }
}
