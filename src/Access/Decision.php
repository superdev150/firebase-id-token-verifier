<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Access;

use Showcase\FirebaseAuth\VerifiedToken;

/** Outcome of an access check, ready to become an HTTP response: `{code}` with `status`. */
final class Decision
{
    private function __construct(
        public readonly bool $allowed,
        public readonly int $status,
        public readonly string $code,
        public readonly ?VerifiedToken $token = null,
    ) {
    }

    public static function allow(VerifiedToken $token): self
    {
        return new self(true, 200, 'ok', $token);
    }

    public static function deny(int $status, string $code, ?VerifiedToken $token = null): self
    {
        return new self(false, $status, $code, $token);
    }
}
