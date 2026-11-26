<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Cache;

/** Per-process cache. Fine for tests and long-running workers; use a shared cache under PHP-FPM. */
final class ArrayCache implements Cache
{
    /** @var array<string, array{0: mixed, 1: int}> */
    private array $items = [];

    /** @param \Closure(): int|null $clock */
    public function __construct(private ?\Closure $clock = null)
    {
    }

    public function get(string $key): mixed
    {
        if (!isset($this->items[$key])) {
            return null;
        }
        [$value, $expires] = $this->items[$key];
        if ($expires <= $this->now()) {
            unset($this->items[$key]);
            return null;
        }
        return $value;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->items[$key] = [$value, $this->now() + $ttlSeconds];
    }

    private function now(): int
    {
        return $this->clock ? ($this->clock)() : time();
    }
}
