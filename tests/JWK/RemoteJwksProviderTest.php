<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\JWK;

use Facile\JoseVerifier\Exception\RuntimeException;
use Facile\JoseVerifier\JWK\RemoteJwksProvider;
use function json_encode;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class RemoteJwksProviderTest extends TestCase
{
    use ProphecyTrait;

    public function testGetJwksShouldFetchFromRemote(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $body = $this->prophesize(StreamInterface::class);
        $uri = 'https://jwks_uri';

        $jwks = ['keys' => []];

        $provider = new RemoteJwksProvider($client->reveal(), $requestFactory->reveal(), $uri);

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request->reveal());

        $client->sendRequest($request->reveal())->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(200);
        $response->getBody()->willReturn($body->reveal());
        $body->__toString()->willReturn(json_encode($jwks));

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testGetJwksShouldFetchFromRemoteWithDefaultHeaders(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $body = $this->prophesize(StreamInterface::class);
        $headers = [
            'accept' => 'application/json',
            'foo' => 'bar',
        ];
        $uri = 'https://jwks_uri';

        $jwks = ['keys' => []];

        $provider = new RemoteJwksProvider($client->reveal(), $requestFactory->reveal(), $uri, $headers);

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request->reveal());
        $request->withHeader('accept', 'application/json')->shouldBeCalled()->will(function () use ($request) {
            $request->withHeader('foo', 'bar')->shouldBeCalled()->willReturn($request->reveal());

            return $request->reveal();
        });

        $client->sendRequest($request->reveal())->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(200);
        $response->getBody()->willReturn($body->reveal());
        $body->__toString()->willReturn(json_encode($jwks));

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testGetJwksShouldFetchFromRemoteWithRequestHeaders(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $body = $this->prophesize(StreamInterface::class);
        $headers = [
            'accept' => 'application/json',
            'foo' => 'bar',
        ];
        $uri = 'https://jwks_uri';

        $jwks = ['keys' => []];

        $provider = (new RemoteJwksProvider($client->reveal(), $requestFactory->reveal(), $uri))
            ->withHeaders($headers);

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request->reveal());
        $request->withHeader('accept', 'application/json')->shouldBeCalled()->will(function () use ($request) {
            $request->withHeader('foo', 'bar')->shouldBeCalled()->willReturn($request->reveal());

            return $request->reveal();
        });

        $client->sendRequest($request->reveal())->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(200);
        $response->getBody()->willReturn($body->reveal());
        $body->__toString()->willReturn(json_encode($jwks));

        $this->assertSame($jwks, $provider->getJwks());
    }

    public function testThrowExceptionOnErrorStatusCode(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to get the key set');
        $this->expectExceptionCode(400);

        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $uri = 'https://jwks_uri';

        $provider = new RemoteJwksProvider($client->reveal(), $requestFactory->reveal(), $uri);

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request->reveal());

        $client->sendRequest($request->reveal())->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(400);

        $provider->getJwks();
    }

    public function testThrowExceptionOnWrongContent(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid key set content');

        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $request = $this->prophesize(RequestInterface::class);
        $response = $this->prophesize(ResponseInterface::class);
        $body = $this->prophesize(StreamInterface::class);
        $uri = 'https://jwks_uri';

        $provider = new RemoteJwksProvider($client->reveal(), $requestFactory->reveal(), $uri);

        $requestFactory->createRequest('GET', $uri)
            ->willReturn($request->reveal());

        $client->sendRequest($request->reveal())->willReturn($response->reveal());
        $response->getStatusCode()->willReturn(200);
        $response->getBody()->willReturn($body->reveal());
        $body->__toString()->willReturn(json_encode([]));

        $provider->getJwks();
    }

    public function testReloadShouldReturnSelf(): void
    {
        $client = $this->prophesize(ClientInterface::class);
        $requestFactory = $this->prophesize(RequestFactoryInterface::class);
        $provider = new RemoteJwksProvider($client->reveal(), $requestFactory->reveal(), 'http://jwks_uri');

        $this->assertSame($provider, $provider->reload());
    }
}
