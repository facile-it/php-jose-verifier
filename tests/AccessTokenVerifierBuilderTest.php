<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest;

use Facile\JoseVerifier\AbstractTokenVerifierBuilder;
use Facile\JoseVerifier\AccessTokenVerifierBuilder;
use Facile\JoseVerifier\JWTVerifier;

class AccessTokenVerifierBuilderTest extends AbstractVerifierBuilderTestCase
{
    protected function getBuilder(): AbstractTokenVerifierBuilder
    {
        return new AccessTokenVerifierBuilder();
    }

    protected function getExpectedVerifierClass(): string
    {
        return JWTVerifier::class;
    }
}
