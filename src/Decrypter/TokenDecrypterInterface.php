<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Decrypter;

use Facile\JoseVerifier\Exception\InvalidTokenException;

interface TokenDecrypterInterface
{
    /**
     * @throws InvalidTokenException
     */
    public function decrypt(string $jwt): ?string;
}
