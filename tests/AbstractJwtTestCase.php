<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Base64Url\Base64Url;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;

use function hash;
use function json_encode;
use function strlen;
use function substr;

class AbstractJwtTestCase extends TestCase
{
    protected function generateHash(string $value): string
    {
        $hash = hash('sha256', $value, true);

        return Base64Url::encode(substr($hash, 0, strlen($hash) / 2));
    }

    protected function createSignedToken(array $payload, array $header, JWK $jwk): string
    {
        return $this->createRawSignedToken((string) json_encode($payload), $header, $jwk);
    }

    protected function createRawSignedToken(string $payload, array $header, JWK $jwk): string
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new HS256(),
        ]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jwsSerializer = new CompactSerializer();

        $jws = $jwsBuilder->create()
            ->withPayload($payload)
            ->addSignature($jwk, $header)
            ->build();

        return $jwsSerializer->serialize($jws);
    }
}
