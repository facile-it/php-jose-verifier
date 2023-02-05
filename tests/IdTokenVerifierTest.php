<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Base64Url\Base64Url;
use Exception;
use Facile\JoseVerifier\Decrypter\NullTokenDecrypter;
use Facile\JoseVerifier\Exception\InvalidTokenClaimException;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use Facile\JoseVerifier\Exception\InvalidTokenExceptionInterface;
use Facile\JoseVerifier\Exception\RuntimeException;
use Facile\JoseVerifier\IdTokenVerifier;
use function Facile\JoseVerifier\jose_secret_key;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Jose\Component\KeyManagement\JWKFactory;
use function random_bytes;
use function time;

class IdTokenVerifierTest extends AbstractTokenVerifierTestCase
{
    protected function buildVerifier(): IdTokenVerifier
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        return new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: $this->authTimeRequired,
            expectedAlg: $this->expectedAlg,
            clientSecret: $this->clientSecret,
            jwksProvider: $this->jwksProvider ?? new MemoryJwksProvider($jwks),
            decrypter: $this->tokenDecrypter ?? new NullTokenDecrypter(),
        );
    }

    public function testShouldValidateIdToken(): void
    {
        $accessToken = Base64Url::encode(random_bytes(32));
        $code = Base64Url::encode(random_bytes(32));
        $state = Base64Url::encode(random_bytes(32));
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'at_hash' => $this->generateHash($accessToken),
            'c_hash' => $this->generateHash($code),
            's_hash' => $this->generateHash($state),
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: true,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier->withNonce('nonce')
            ->withAccessToken($accessToken)
            ->withCode($code)
            ->withState($state)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldValidateWithMultiTenant(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com/office',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'tid' => 'office',
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com/{tenantid}',
            'client-id',
            aadIssValidation: true,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldValidateWithValidMaxAge(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time(),
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier->withMaxAge(1)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithInvalidAuthTime(): void
    {
        $this->expectException(InvalidTokenClaimException::class);

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time() - 5,
            'auth_time' => time() - 30,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $verifier->withMaxAge(1)
            ->verify($token);
    }

    public function testShouldNotFailWithOldAuthTimeButHighClockTolerance(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time() - 5,
            'auth_time' => time() - 30,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            clockTolerance: 60,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier->withMaxAge(1)
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

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: true,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $verifier->withNonce('nonce')
            ->verify($token);
    }

    public function testShouldFailWithBadAccessTokenHash(): void
    {
        $this->expectException(InvalidTokenClaimException::class);

        $accessToken = Base64Url::encode(random_bytes(32));
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
            'at_hash' => 'bad-hash',
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: true,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier->withNonce('nonce')
            ->withAccessToken($accessToken)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithBadCodeHash(): void
    {
        $this->expectException(InvalidTokenClaimException::class);

        $code = Base64Url::encode(random_bytes(32));
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
            'c_hash' => 'bad-hash',
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: true,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier->withNonce('nonce')
            ->withCode($code)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithBadStateHash(): void
    {
        $this->expectException(InvalidTokenClaimException::class);

        $state = Base64Url::encode(random_bytes(32));
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
            's_hash' => 'bad-hash',
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            authTimeRequired: true,
            expectedAlg: 'RS256',
            jwksProvider: new MemoryJwksProvider($jwks)
        );

        $result = $verifier
            ->withNonce('nonce')
            ->withState($state)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function verifyIdTokenProvider(): array
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
            // wrong nonce
            [
                [
                    'iss' => 'https://issuer.com',
                    'sub' => 'client-id',
                    'aud' => 'client-id',
                    'exp' => time() + 600,
                    'iat' => time(),
                    'auth_time' => time() - 100,
                    'nonce' => 'bad-nonce',
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
     * @dataProvider verifyIdTokenProvider
     *
     * @throws Exception
     */
    public function testValidateIdTokenWithAsyKey(array $payload, bool $expected): void
    {
        if (! $expected) {
            $this->expectException(InvalidTokenExceptionInterface::class);
        }

        $clientSecret = Base64Url::encode(random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            clientSecret: $clientSecret,
            authTimeRequired: true,
            expectedAlg: 'HS256',
            jwksProvider: new MemoryJwksProvider()
        );

        $result = $verifier
            ->withNonce('nonce')
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithAsyKeyAndNoSecret(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Signature requires client_secret to be verified');

        $clientSecret = Base64Url::encode(random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

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
            'alg' => 'HS256',
        ], $jwk);

        $verifier = new IdTokenVerifier(
            'https://issuer.com',
            'client-id',
            expectedAlg: 'HS256',
            jwksProvider: new MemoryJwksProvider()
        );

        $verifier->verify($token);
    }
}
