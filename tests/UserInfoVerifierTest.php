<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Base64Url\Base64Url;
use Exception;
use Facile\JoseVerifier\Decrypter\NullTokenDecrypter;
use Facile\JoseVerifier\Exception\InvalidTokenClaimException;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use Facile\JoseVerifier\Exception\InvalidTokenExceptionInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\UserInfoVerifier;
use Jose\Component\KeyManagement\JWKFactory;

use function Facile\JoseVerifier\jose_secret_key;
use function random_bytes;
use function time;

class UserInfoVerifierTest extends AbstractTokenVerifierTestCase
{
    protected function buildVerifier(): UserInfoVerifier
    {
        $jwk = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        return new UserInfoVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: $this->authTimeRequired,
            expectedAlg: $this->expectedAlg,
            expectedAzp: $this->expectedAzp,
            clientSecret: $this->clientSecret,
            jwksProvider: $this->jwksProvider ?? new MemoryJwksProvider($jwks),
            decrypter: $this->tokenDecrypter ?? new NullTokenDecrypter(),
        );
    }

    public function testShouldValidateToken(): void
    {
        $jwk = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'sub' => 'client-id',
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $this->expectedAlg = 'RS256';
        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $result = $this->buildVerifier()
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithoutKey(): void
    {
        $this->expectException(InvalidTokenException::class);

        $jwk = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwk2 = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk2->toPublic()->all()]];

        $this->authTimeRequired = true;
        $this->expectedAlg = 'RS256';
        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $this->buildVerifier()
            ->withNonce('nonce')
            ->verify($token);
    }

    public static function verifyTokenProvider(): array
    {
        return [
            'valid sub' => [
                [
                    'sub' => 'client-id',
                ],
                true,
            ],
            'wrong iss' => [
                [
                    'iss' => 'https://issuer.com-wrong',
                    'sub' => 'client-id',
                ],
                false,
            ],
            'wrong aud' => [
                [
                    'sub' => 'client-id',
                    'aud' => 'wrong-client-id',
                ],
                false,
            ],
            'wrong exp' => [
                [
                    'sub' => 'client-id',
                    'exp' => time() - 1,
                ],
                false,
            ],
            'missing sub' => [
                [
                ],
                false,
            ],
        ];
    }

    /**
     * @dataProvider verifyTokenProvider
     *
     * @throws Exception
     */
    public function testValidateTokenWithAsyKey(array $payload, bool $expected): void
    {
        if (! $expected) {
            $this->expectException(InvalidTokenExceptionInterface::class);
        }

        $clientSecret = Base64Url::encode(random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $this->authTimeRequired = true;
        $this->expectedAlg = 'HS256';
        $this->clientSecret = $clientSecret;
        $this->jwksProvider = new MemoryJwksProvider();

        $verifier = $this->buildVerifier()
            ->withNonce('nonce');

        $result = $verifier->verify($token);

        self::assertSame($payload, $result);

        self::assertSame($payload, $result);
    }

    public function testWithWrongAzp(): void
    {
        $this->expectException(InvalidTokenClaimException::class);

        $payload = [
            'sub' => 'sub-id',
            'azp' => 'foo',
        ];

        $clientSecret = Base64Url::encode(random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $this->authTimeRequired = true;
        $this->expectedAlg = 'HS256';
        $this->clientSecret = $clientSecret;
        $this->expectedAzp = 'client-id';
        $this->jwksProvider = new MemoryJwksProvider();

        $verifier = $this->buildVerifier()
            ->withNonce('nonce');

        $verifier->verify($token);
    }
}
