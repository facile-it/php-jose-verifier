<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Base64Url\Base64Url;
use Exception;
use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use Facile\JoseVerifier\Exception\RuntimeException;
use Facile\JoseVerifier\IdTokenVerifier;
use function Facile\JoseVerifier\jose_secret_key;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Jose\Component\KeyManagement\JWKFactory;
use function random_bytes;
use function time;

class IdTokenVerifierTest extends AbstractTokenVerifierTestCase
{
    /**
     * @return IdTokenVerifier
     */
    protected function buildVerifier(TokenDecrypterInterface $decrypter = null): AbstractTokenVerifier
    {
        return new IdTokenVerifier('https://issuer.com', 'client-id', $decrypter);
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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
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

        $verifier = new IdTokenVerifier('https://issuer.com/{tenantid}', 'client-id');
        $result = $verifier
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withExpectedAlg('RS256')
            ->withAadIssValidation(true)
            ->verify($token);

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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withExpectedAlg('RS256')
            ->withMaxAge(1)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithInvalidAuthTime(): void
    {
        $this->expectException(InvalidTokenException::class);

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

        $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withExpectedAlg('RS256')
            ->withMaxAge(1)
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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withExpectedAlg('RS256')
            ->withMaxAge(1)
            ->withClockTolerance(60)
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
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
            ->verify($token);
    }

    public function testShouldFailWithBadAccessTokenHash(): void
    {
        $this->expectException(InvalidTokenException::class);

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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
            ->withAccessToken($accessToken)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithBadCodeHash(): void
    {
        $this->expectException(InvalidTokenException::class);

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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
            ->withCode($code)
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldFailWithBadStateHash(): void
    {
        $this->expectException(InvalidTokenException::class);

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

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
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
            $this->expectException(InvalidTokenException::class);
        }

        $clientSecret = Base64Url::encode(random_bytes(32));
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

        $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider())
            ->withExpectedAlg('HS256')
            ->verify($token);
    }
}
