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

    protected bool $authTimeRequired = false;

    protected ?string $expectedAlg = null;

    protected ?string $expectedAzp = null;

    protected ?string $clientSecret = null;

    protected ?JwksProviderInterface $jwksProvider = null;

    protected ?TokenDecrypterInterface $tokenDecrypter = null;

    protected function setUp(): void
    {
        $this->authTimeRequired = false;
        $this->expectedAlg = null;
        $this->expectedAzp = null;
        $this->clientSecret = null;
        $this->jwksProvider = null;
        $this->tokenDecrypter = null;
    }

    abstract protected function buildVerifier(): AbstractTokenVerifier;

    public function testShouldReloadJwksWhenKidNotFound(): void
    {
        $jwk1 = JWKFactory::createRSAKey(2_048, [
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'kid1',
        ]);
        $jwk2 = JWKFactory::createRSAKey(2_048, [
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

        $this->authTimeRequired = true;
        $this->expectedAlg = 'RS256';
        $this->jwksProvider = $jwksProvider->reveal();

        $result = $this->buildVerifier()
            ->withNonce('nonce')
            ->verify($token);

        self::assertSame($payload, $result);
    }

    public function testShouldUseDecrypter(): void
    {
        $decrypter = $this->prophesize(TokenDecrypterInterface::class);

        $jwk = JWKFactory::createRSAKey(2_048, [
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

        $decrypter->decrypt('foo')->shouldBeCalled()->willReturn($token);

        $this->authTimeRequired = true;
        $this->expectedAlg = 'RS256';
        $this->jwksProvider = new MemoryJwksProvider($jwks);
        $this->tokenDecrypter = $decrypter->reveal();

        $result = $this->buildVerifier()->verify('foo');

        self::assertSame($payload, $result);
    }

    public function testShouldFailValidateSignatureOnNoKidFound(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Unable to find the jwk with the provided kid: kid2');

        $jwk1 = JWKFactory::createRSAKey(2_048, [
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

        $this->authTimeRequired = true;
        $this->expectedAlg = 'RS256';
        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $this->buildVerifier()->verify($token);
    }

    public function testFailWithInvalidJWT(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid JWT provided');

        $jwk = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $this->buildVerifier()->verify('');
    }

    public function testFailWithInvalidJWTPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $jwk = JWKFactory::createRSAKey(2_048, ['alg' => 'RS256', 'use' => 'sig']);
        $token = $this->createRawSignedToken('foo', [
            'alg' => 'RS256',
        ], $jwk);

        $jwks = ['keys' => [$jwk->toPublic()->all()]];

        $this->jwksProvider = new MemoryJwksProvider($jwks);

        $this->buildVerifier()->verify($token);
    }
}
