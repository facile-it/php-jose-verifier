<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test\Validate;

use Facile\JoseVerifier\Exception\InvalidTokenClaimException;
use Facile\JoseVerifier\Exception\RuntimeException;
use Facile\JoseVerifier\Internal\Validate;
use Facile\JoseVerifier\Test\AbstractJwtTestCase;
use Facile\JoseVerifier\Test\ClaimChecker\CallableChecker;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;

class ValidateTest extends AbstractJwtTestCase
{
    /** @var \Jose\Component\Core\JWK */
    private $jwk;

    /** @var JWKSet */
    private $jwks;

    protected function setUp(): void
    {
        $this->jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $this->jwks = JWKSet::createFromKeyData(['keys' => [$this->jwk->toPublic()->all()]]);
    }

    public function createPayload(): array
    {
        return [
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ];
    }

    private function generateTokenWithPayload(array $payload): string
    {
        return $this->createSignedToken($payload, [
            'alg' => 'RS256',
        ], $this->jwk);
    }

    private function generateToken(): string
    {
        return $this->generateTokenWithPayload([
            'iss' => 'https://issuer.com',
            'sub' => 'client-id',
            'aud' => 'client-id',
            'azp' => 'client-id',
            'exp' => time() + 600,
            'iat' => time(),
            'auth_time' => time() - 100,
        ]);
    }

    public function testShouldValidateSignature(): void
    {
        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::withToken($token);
        $validator = $baseValidator->withJWKSet($this->jwks);

        $this->assertNotSame($validator, $baseValidator);
        $this->assertSame($payload, $validator->run());
    }

    public function testShouldValidateSignatureFail(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid token signature');

        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::withToken($token);

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = JWKSet::createFromKeyData(['keys' => [$jwk->toPublic()->all()]]);

        $validator = $baseValidator->withJWKSet($jwks);

        $this->assertNotSame($validator, $baseValidator);
        $validator->run();
    }

    public function testShouldValidateClaim(): void
    {
        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::withToken($token)
            ->withJWKSet($this->jwks);
        $validator = $baseValidator->withClaim(new CallableChecker('aud', static function () {
            return true;
        }));

        $this->assertNotSame($validator, $baseValidator);
        $this->assertSame($payload, $validator->run());
    }

    public function testShouldValidateClaimFail(): void
    {
        $this->expectException(InvalidTokenClaimException::class);

        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::withToken($token)
            ->withJWKSet($this->jwks);
        $validator = $baseValidator->withClaim(new CallableChecker('aud', static function () {
            return false;
        }));

        $this->assertNotSame($validator, $baseValidator);
        $validator->run();
    }

    public function testShouldValidateHeader(): void
    {
        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::withToken($token)
            ->withJWKSet($this->jwks);
        $validator = $baseValidator->withHeader(new AlgorithmChecker(['foo', 'RS256']));

        $this->assertNotSame($validator, $baseValidator);
        $this->assertSame($payload, $validator->run());
    }

    public function testShouldValidateHeaderFail(): void
    {
        $this->expectException(InvalidHeaderException::class);

        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::withToken($token)
            ->withJWKSet($this->jwks);
        $validator = $baseValidator->withHeader(new AlgorithmChecker(['foo', 'bar']));

        $this->assertNotSame($validator, $baseValidator);
        $validator->run();
    }
}
