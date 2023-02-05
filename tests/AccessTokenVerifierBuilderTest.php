<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Test;

use Facile\JoseVerifier\Builder\AccessTokenVerifierBuilder;
use Facile\JoseVerifier\JWTVerifier;

class AccessTokenVerifierBuilderTest extends AbstractVerifierBuilderTestCase
{
    protected function getBuilder(array $issuerMetadata, array $clientMetadata): AccessTokenVerifierBuilder
    {
        return AccessTokenVerifierBuilder::create($issuerMetadata, $clientMetadata);
    }

    protected function getExpectedVerifierClass(): string
    {
        return JWTVerifier::class;
    }
}
