<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Cache;

/**
 * The smallest cache the verifier needs. Adapt your framework's cache in three lines
 * (see examples/laravel-middleware.php).
 */
interface Cache
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds): void;
}
