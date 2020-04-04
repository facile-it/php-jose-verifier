<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest\JWK;

use Facile\JoseVerifier\JWK\CachedJwksProvider;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use function json_encode;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Psr\SimpleCache\CacheInterface;

class CachedJwksProviderTest extends TestCase
{
    public function testGetJwksShouldSaveCacheWithoutTtl(): void
    {
        $wrappedProvider = $this->prophesize(JwksProviderInterface::class);
        $cache = $this->prophesize(CacheInterface::class);

        $provider = new CachedJwksProvider($wrappedProvider->reveal(), $cache->reveal(), 'cache_key', null);

        $jwks = ['keys' => [['foo' => 'bar']]];

        $wrappedProvider->getJwks()->shouldBeCalled()->willReturn($jwks);
        $cache->get('cache_key')->shouldBeCalled()->willReturn(null);
        $cache->set('cache_key', json_encode($jwks), null)->shouldBeCalled();

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testGetJwksShouldSaveCacheWithTtl(): void
    {
        $wrappedProvider = $this->prophesize(JwksProviderInterface::class);
        $cache = $this->prophesize(CacheInterface::class);

        $provider = new CachedJwksProvider($wrappedProvider->reveal(), $cache->reveal(), 'cache_key', 5);

        $jwks = ['keys' => [['foo' => 'bar']]];

        $wrappedProvider->getJwks()->shouldBeCalled()->willReturn($jwks);
        $cache->get('cache_key')->shouldBeCalled()->willReturn(null);
        $cache->set('cache_key', json_encode($jwks), 5)->shouldBeCalled();

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testGetJwksShouldFetchFromCache(): void
    {
        $wrappedProvider = $this->prophesize(JwksProviderInterface::class);
        $cache = $this->prophesize(CacheInterface::class);

        $provider = new CachedJwksProvider($wrappedProvider->reveal(), $cache->reveal(), 'cache_key', 5);

        $jwks = ['keys' => [['foo' => 'bar']]];

        $wrappedProvider->getJwks()->shouldNotBeCalled();
        $cache->get('cache_key')->shouldBeCalled()->willReturn(json_encode($jwks));
        $cache->set(Argument::cetera())->shouldNotBeCalled();

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testReloadShouldDeleteCache(): void
    {
        $wrappedProvider = $this->prophesize(JwksProviderInterface::class);
        $cache = $this->prophesize(CacheInterface::class);

        $provider = new CachedJwksProvider($wrappedProvider->reveal(), $cache->reveal(), 'cache_key', 5);

        $cache->delete('cache_key')->shouldBeCalled();

        $this->assertSame($provider, $provider->reload());
    }
}
