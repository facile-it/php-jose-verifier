<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Decrypter\TokenDecrypterInterface;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\JWK\MemoryJwksProvider;
use Jose\Component\KeyManagement\JWKFactory;
use Prophecy\PhpUnit\ProphecyTrait;
use function time;

abstract class AbstractTokenVerifierTestCase extends AbstractJwtTestCase
{
    use ProphecyTrait;

    abstract protected function buildVerifier(TokenDecrypterInterface $decrypter = null): AbstractTokenVerifier;

    public function testShouldReloadJwksWhenKidNotFound(): void
    {
        $jwk1 = JWKFactory::createRSAKey(2048, [
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'kid1',
        ]);
        $jwk2 = JWKFactory::createRSAKey(2048, [
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'kid2',
        ]);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
            'kid' => 'kid2',
        ], $jwk2);

        $jwks = ['keys' => [
            $jwk1->toPublic()->all(),
        ]];

        $jwks2 = ['keys' => [
            $jwk1->toPublic()->all(),
            $jwk2->toPublic()->all(),
        ]];

        $jwksProvider = $this->prophesize(JwksProviderInterface::class);
        $jwksProvider->getJwks()->shouldBeCalled()->willReturn($jwks);
        $jwksProvider->reload()->shouldBeCalled()->will(function () use ($jwksProvider, $jwks2) {
            $jwksProvider->getJwks()->shouldBeCalled()->willReturn($jwks2);

            return $jwksProvider->reveal();
        });

        $result = $this->buildVerifier()
            ->withJwksProvider($jwksProvider->reveal())
            ->withAuthTimeRequired(true)
            ->withNonce('nonce')
            ->withExpectedAlg('RS256')
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldUseDecrypter(): void
    {
        $decrypter = $this->prophesize(TokenDecrypterInterface::class);

        $jwk = JWKFactory::createRSAKey(2048, [
            'alg' => 'RS256',
            'use' => 'sig',
        ]);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [
            $jwk->toPublic()->all(),
        ]];

        $jwksProvider = new MemoryJwksProvider($jwks);

        $decrypter->decrypt('foo')->shouldBeCalled()->willReturn($token);

        $result = $this->buildVerifier($decrypter->reveal())
            ->withJwksProvider($jwksProvider)
            ->withExpectedAlg('RS256')
            ->verify('foo');

        self::assertSame($payload, $result);
    }

    public function testShouldFailValidateSignatureOnNoKidFound(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Unable to find the jwk with the provided kid: kid2');

        $jwk1 = JWKFactory::createRSAKey(2048, [
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'kid1',
        ]);
        $payload = [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
        $token = $this->createSignedToken($payload, [
            'alg' => 'RS256',
            'kid' => 'kid2',
        ], $jwk1);

        $jwks = ['keys' => [
            $jwk1->toPublic()->all(),
        ]];

        $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->withAuthTimeRequired(true)
            ->withExpectedAlg('RS256')
            ->verify($token);
    }

    public function testFailWithInvalidJWT(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid JWT provided');

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->verify('');
    }

    public function testFailWithInvalidJWTPayload(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Unable to decode JWT payload');

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $token = $this->createRawSignedToken('foo', [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $this->buildVerifier()
            ->withJwksProvider(new MemoryJwksProvider($jwks))
            ->verify($token);
    }
}
