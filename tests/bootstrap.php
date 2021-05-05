<?php

declare(strict_types=1);

namespace Prophecy\PhpUnit {
    use function trait_exists;

    if (! trait_exists(\Prophecy\PhpUnit\ProphecyTrait::class)) {
        trait ProphecyTrait
        {
        }
    }
}
