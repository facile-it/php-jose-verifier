<?php

declare(strict_types=1);

namespace Facile\JoseVerifier\Validate;

use function array_merge;
use Jose\Component\Signature\Algorithm\None;

class Validate extends \Jose\Easy\Validate
{
    /**
     * @return string[]
     */
    protected function getAlgorithmMap(): array
    {
        return array_merge(
            [None::class],
            parent::getAlgorithmMap()
        );
    }
}
