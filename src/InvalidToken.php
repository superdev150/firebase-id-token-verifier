<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth;

/**
 * Thrown when a token must be rejected. `reason` is a stable, machine-readable code that is safe to log
 * (never log the token itself).
 */
final class InvalidToken extends \RuntimeException
{
    public function __construct(public readonly string $reason, string $message = '', ?\Throwable $previous = null)
    {
        parent::__construct($message !== '' ? $message : $reason, 0, $previous);
    }
}
