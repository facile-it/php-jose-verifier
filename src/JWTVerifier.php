<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use Jose\Easy\Validate;
use Throwable;

final class JWTVerifier extends AbstractTokenVerifier
{
    public function verify(string $jwt): array
    {
        $jwt = $this->decrypt($jwt);
        /** @var Validate $validator */
        $validator = $this->create($jwt)
            ->mandatory(['iss', 'sub', 'aud', 'exp', 'iat']);

        try {
            return $validator->run()->claims->all();
        } catch (Throwable $e) {
            throw $this->processException($e);
        }
    }
}
