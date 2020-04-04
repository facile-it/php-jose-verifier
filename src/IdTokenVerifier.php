<?php

declare(strict_types=1);

namespace Facile\JoseVerifier;

use function array_key_exists;
use Facile\JoseVerifier\ClaimChecker\AtHashChecker;
use Facile\JoseVerifier\ClaimChecker\CHashChecker;
use Facile\JoseVerifier\ClaimChecker\SHashChecker;
use Facile\JoseVerifier\Exception\RuntimeException;
use Jose\Easy\Validate;
use Throwable;

final class IdTokenVerifier extends AbstractTokenVerifier implements IdTokenVerifierInterface
{
    /** @var string|null */
    protected $accessToken;

    /** @var string|null */
    protected $code;

    /** @var string|null */
    protected $state;

    /**
     * @param string|null $accessToken
     *
     * @return $this
     */
    public function withAccessToken(?string $accessToken): self
    {
        $new = clone $this;
        $new->accessToken = $accessToken;

        return $new;
    }

    /**
     * @param string|null $code
     *
     * @return $this
     */
    public function withCode(?string $code): self
    {
        $new = clone $this;
        $new->code = $code;

        return $new;
    }

    /**
     * @param string|null $state
     *
     * @return $this
     */
    public function withState(?string $state): self
    {
        $new = clone $this;
        $new->state = $state;

        return $new;
    }

    public function verify(string $jwt): array
    {
        $jwt = $this->decrypt($jwt);
        $validator = $this->create($jwt);
        $payload = $this->getPayload($jwt);

        $requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];

        if (null !== $this->accessToken) {
            $requiredClaims[] = 'at_hash';
            $validator = $validator->claim('s_hash', new AtHashChecker($this->accessToken, $header['alg'] ?? ''));
        }

        if (null !== $this->code) {
            $requiredClaims[] = 'c_hash';
            $validator = $validator->claim('s_hash', new CHashChecker($this->code, $header['alg'] ?? ''));
        }

        if (array_key_exists('s_hash', $payload)) {
            if (null === $this->state) {
                throw new RuntimeException('Cannot verify s_hash, "state" not provided');
            }

            $validator = $validator->claim('s_hash', new SHashChecker($this->state, $header['alg'] ?? ''));
        }

        /** @var Validate $validator */
        $validator = $validator->mandatory($requiredClaims);

        try {
            return $validator->run()->claims->all();
        } catch (Throwable $e) {
            throw $this->processException($e);
        }
    }
}
