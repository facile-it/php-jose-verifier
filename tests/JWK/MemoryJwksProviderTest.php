<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\JWK;

use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use PHPUnit\Framework\TestCase;

class MemoryJwksProviderTest extends TestCase
{
    public function testShouldInitializeWithValidJwks(): void
    {
        $provider = new MemoryJwksProvider();

        $this->assertSame(['keys' => []], $provider->getJwks());
    }

    public function testShouldInitializeWithProvidedJwks(): void
    {
        $jwks = ['keys' => [['foo' => 'bar']]];

        $provider = new MemoryJwksProvider($jwks);

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testReloadShouldReturnSelf(): void
    {
        $provider = new MemoryJwksProvider();

        $this->assertSame($provider, $provider->reload());
    }
}
