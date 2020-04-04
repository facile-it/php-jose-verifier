<?php

declare(strict_types=1);

namespace Facile\JoseVerifierTest;

use Facile\JoseVerifier\AbstractTokenVerifierBuilder;
use Facile\JoseVerifier\AccessTokenVerifier;
use Facile\JoseVerifier\AccessTokenVerifierBuilder;

class AccessTokenVerifierBuilderTest extends AbstractVerifierBuilderTestCase
{
    protected function getBuilder(): AbstractTokenVerifierBuilder
    {
        return new AccessTokenVerifierBuilder();
    }

    protected function getExpectedVerifierClass(): string
    {
        return AccessTokenVerifier::class;
    }
}
