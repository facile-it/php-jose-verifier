<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest;

use Base64Url\Base64Url;
use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use function Facile\JoseVerifier\jose_secret_key;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Facile\JoseVerifier\UserInfoVerifier;
use Jose\Component\KeyManagement\JWKFactory;
use function time;

class UserInfoVerifierTest extends AbstractTokenVerifierTestCase
{
    /**
     * @param TokenDecrypterInterface|null $decrypter
     *
     * @return UserInfoVerifier
     */
    protected function buildVerifier(TokenDecrypterInterface $decrypter = null): AbstractTokenVerifier
    {
        return new UserInfoVerifier('https://issuer.com', 'client-id', $decrypter);
    }

    public function testShouldValidateToken(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $payload = [
            'sub' => 'client-id',
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $result = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
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
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
            ->verify($token);
    }

    public function verifyTokenProvider(): array
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

        $verifier = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider())
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withClientSecret($clientSecret)
            ->withExpectedAlg('HS256');

        $result = $verifier->verify($token);

        self::assertSame($payload, $result);

        self::assertSame($payload, $result);
    }

    public function testWithWrongAzp(): void
    {
        $this->expectException(InvalidTokenException::class);

        $payload = [
            'sub' => 'sub-id',
            'azp' => 'foo',
        ];

        $clientSecret = Base64Url::encode(\random_bytes(32));
        $jwk = jose_secret_key($clientSecret);

        $token = $this->createSignedToken($payload, [
            'alg' => 'HS256',
        ], $jwk);

        $verifier = $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider())
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withClientSecret($clientSecret)
            ->withExpectedAlg('HS256')
            ->withAzp('client-id');

        $verifier->verify($token);
    }
}
