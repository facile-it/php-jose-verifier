<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\JWK;

use function array_key_exists;
use Facile\JoseVerifier\Exception\RuntimeException;
use function is_array;
use function json_decode;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Provide a {@see JwksProviderInterface} to fetch JWKSet from a remote location.
 *
 * @psalm-api
 *
 * @psalm-import-type JWKSetType from JwksProviderInterface
 */
final class RemoteJwksProvider implements JwksProviderInterface
{
    private ClientInterface $client;

    private RequestFactoryInterface $requestFactory;

    private string $uri;

    /** @var array<string, string|string[]> */
    private array $headers;

    /**
     * @param array<string, string|string[]> $headers
     */
    public function __construct(
        ClientInterface $client,
        RequestFactoryInterface $requestFactory,
        string $uri,
        array $headers = []
    ) {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->uri = $uri;
        $this->headers = $headers;
    }

    /**
     * @param array<string, string|string[]> $headers
     */
    public function withHeaders(array $headers): static
    {
        $new = clone $this;
        $new->headers = $headers;

        return $new;
    }

    /**
     * @throws RuntimeException Whenever a runtime error occurred
     */
    public function getJwks(): array
    {
        $request = $this->requestFactory->createRequest('GET', $this->uri);

        foreach ($this->headers as $k => $v) {
            /** @var RequestInterface $request */
            $request = $request->withHeader($k, $v);
        }

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RuntimeException('An error occurred fetching JWKSet', 0, $e);
        }

        if ($response->getStatusCode() >= 400) {
            throw new RuntimeException('Unable to get the key set', $response->getStatusCode());
        }

        try {
            /** @var mixed $data */
            $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to decode response payload', 0, $e);
        }

        if ($this->isJWKSet($data)) {
            /** @var JWKSetType $data */
            return $data;
        }

        throw new RuntimeException('Invalid key set content');
    }

    /**
     * @param mixed $data
     *
     * @psalm-assert-if-true JWKSetType $data
     */
    private function isJWKSet($data): bool
    {
        return is_array($data) && array_key_exists('keys', $data) && is_array($data['keys']);
    }

    public function reload(): static
    {
        return $this;
    }
}
