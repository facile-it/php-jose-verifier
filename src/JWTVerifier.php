<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use Facile\JoseVerifier\Exception\InvalidTokenClaimException;
use Facile\JoseVerifier\Exception\InvalidTokenException;

final class JWTVerifier extends AbstractTokenVerifier
{
    public function verify(string $jwt): array
    {
        $jwt = $this->decrypt($jwt);
        $validator = $this->create($jwt)
            ->withMandatory(['iss', 'sub', 'aud', 'exp', 'iat']);

        return $validator->run();
    }
}
