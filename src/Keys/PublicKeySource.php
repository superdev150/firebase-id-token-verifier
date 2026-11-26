<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Keys;

interface PublicKeySource
{
    /**
     * @param bool $refresh skip the cache (the token names a key id we do not know yet: Google rotated its keys)
     * @return array<string, string> key id → PEM certificate
     */
    public function keys(bool $refresh = false): array;
}
