<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Base64Url\Base64Url;
use Exception;
use Facile\JoseVerifier\Decrypter\NullTokenDecrypter;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use Facile\JoseVerifier\Exception\InvalidTokenExceptionInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\JWTVerifier;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;

use function Facile\JoseVerifier\jose_secret_key;
use function random_bytes;
use function time;

class JWTVerifierTest extends AbstractTokenVerifierTestCase
{
    protected function buildVerifier(): JWTVerifier
    {
        $jwk = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        return new JWTVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: $this->authTimeRequired,
            expectedAlg: $this->expectedAlg,
            clientSecret: $this->clientSecret,
            jwksProvider: $this->jwksProvider ?? new MemoryJwksProvider($jwks),
            decrypter: $this->tokenDecrypter ?? new NullTokenDecrypter(),
        );
    }

    public function testShouldValidateToken(): void
    {
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

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $this->authTimeRequired = true;
        $this->expectedAlg = 'RS256';
        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $result = $this->buildVerifier()
            ->withNonce('nonce')
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

        $this->expectedAlg = 'RS256';
        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $this->buildVerifier()->verify($token);
    }

    public static function verifyTokenProvider(): array
    {
        return [
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'azp' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                true,
            ],
            // wrong issuer
            [
                [
                    'iss' => 'https://issuer.com-wrong',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong aud
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'wrong-client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong exp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // wrong auth_time
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'auth_time' => time() - 400,
                ],
                false,
            ],
            // wrong azp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() - 1,
                    'iat' => time(),
                    'azp' => 'foo',
                    'auth_time' => time() - 400,
                ],
                false,
            ],
            // missing sub
            [
                [
                    'iss' => 'https://issuer.com',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing iss
            [
                [
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 300,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing aud
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'exp' => time() + 300,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing exp
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'iat' => time(),
                    'auth_time' => time() - 100,
                ],
                false,
            ],
            // missing iat
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 300,
                    'auth_time' => time() - 100,
                ],
                false,
            ],
        ];
    }

    /**
     * @throws Exception
     */
    #[DataProvider('verifyTokenProvider')]
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

        $result = $this->buildVerifier()
            ->withNonce('nonce')
            ->verify($token);

        self::assertSame($payload, $result);

        self::assertSame($payload, $result);
    }
}
