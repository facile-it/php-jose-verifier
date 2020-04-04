<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

interface IdTokenVerifierInterface extends TokenVerifierInterface
{
    /**
     * @param string|null $accessToken
     *
     * @return $this
     */
    public function withAccessToken(?string $accessToken);

    /**
     * @param string|null $code
     *
     * @return $this
     */
    public function withCode(?string $code);

    /**
     * @param string|null $state
     *
     * @return $this
     */
    public function withState(?string $state);
}
