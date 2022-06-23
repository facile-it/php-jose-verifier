<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest\Validate;

use Facile\JoseVerifier\Checker\CallableChecker;
use Facile\JoseVerifier\Exception\RuntimeException;
use Facile\JoseVerifier\Validate\Validate;
use Facile\JoseVerifierTest\AbstractJwtTestCase;
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
        $baseValidator = Validate::token($token);
        $validator = $baseValidator->keyset($this->jwks);

        $this->assertNotSame($validator, $baseValidator);
        $this->assertSame($payload, $validator->run());
    }

    public function testShouldValidateSignatureFail(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid signature');

        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::token($token);

        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $jwks = JWKSet::createFromKeyData(['keys' => [$jwk->toPublic()->all()]]);

        $validator = $baseValidator->keyset($jwks);

        $this->assertNotSame($validator, $baseValidator);
        $validator->run();
    }

    public function testShouldValidateClaim(): void
    {
        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::token($token)
            ->keyset($this->jwks);
        $validator = $baseValidator->claim(new CallableChecker('aud', static function () {
            return true;
        }));

        $this->assertNotSame($validator, $baseValidator);
        $this->assertSame($payload, $validator->run());
    }

    public function testShouldValidateClaimFail(): void
    {
        $this->expectException(InvalidClaimException::class);

        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::token($token)
            ->keyset($this->jwks);
        $validator = $baseValidator->claim(new CallableChecker('aud', static function () {
            return false;
        }));

        $this->assertNotSame($validator, $baseValidator);
        $validator->run();
    }

    public function testShouldValidateHeader(): void
    {
        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::token($token)
            ->keyset($this->jwks);
        $validator = $baseValidator->header(new AlgorithmChecker(['foo', 'RS256']));

        $this->assertNotSame($validator, $baseValidator);
        $this->assertSame($payload, $validator->run());
    }

    public function testShouldValidateHeaderFail(): void
    {
        $this->expectException(InvalidHeaderException::class);

        $payload = $this->createPayload();
        $token = $this->generateTokenWithPayload($payload);
        $baseValidator = Validate::token($token)
            ->keyset($this->jwks);
        $validator = $baseValidator->header(new AlgorithmChecker(['foo', 'bar']));

        $this->assertNotSame($validator, $baseValidator);
        $validator->run();
    }
}
