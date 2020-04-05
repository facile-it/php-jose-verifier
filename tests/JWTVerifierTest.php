<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest;

use Base64Url\Base64Url;
use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use function Facile\JoseVerifier\jose_secret_key;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\JWTVerifier;
use Jose\Component\KeyManagement\JWKFactory;
use function time;

class JWTVerifierTest extends AbstractTokenVerifierTestCase
{
    /**
     * @param TokenDecrypterInterface|null $decrypter
     *
     * @return JWTVerifier
     */
    protected function buildVerifier(TokenDecrypterInterface $decrypter = null): AbstractTokenVerifier
    {
        return new JWTVerifier('https://issuer.com', 'client-id', $decrypter);
    }

    public function testShouldValidateToken(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithoutKey(): void
    {
        $this->expectException(InvalidTokenException::class);

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
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

        $jwk2 = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk2->toPublic()->all()]];

        $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withExpectedAlg('RS256')
            ->verify($token);
    }

    public function verifyTokenProvider(): array
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
     * @dataProvider verifyTokenProvider
     *
     * @param array $payload
     * @param bool $expected
     *
     * @throws \Exception
     */
    public function testValidateTokenWithAsyKey(array $payload, bool $expected): void
    {
        if (! $expected) {
            $this->expectException(InvalidTokenException::class);
        }

        $clientSecret = Base64Url::encode(\random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider())
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withClientSecret($clientSecret)
            ->withExpectedAlg('HS256')
            ->verify($token);

        self::assertSame($payload, $result);

        self::assertSame($payload, $result);
    }
}
