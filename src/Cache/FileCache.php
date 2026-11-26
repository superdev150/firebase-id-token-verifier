<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Cache;

/**
 * Shared between PHP-FPM workers through a directory. Writes go to a temp file and are renamed into place, so a reader
 * never sees half a file.
 */
final class FileCache implements Cache
{
    public function __construct(private string $directory)
    {
        if (!is_dir($directory) && !@mkdir($directory, 0770, true) && !is_dir($directory)) {
            throw new \RuntimeException("Cannot create cache directory {$directory}");
        }
    }

    public function get(string $key): mixed
    {
        $raw = @file_get_contents($this->path($key));
        if ($raw === false) {
            return null;
        }
        $item = json_decode($raw, true);
        if (!is_array($item) || ($item['expires'] ?? 0) <= time()) {
            return null;
        }
        return $item['value'] ?? null;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $tmp = tempnam($this->directory, 'tmp');
        file_put_contents($tmp, json_encode(['expires' => time() + $ttlSeconds, 'value' => $value]));
        rename($tmp, $this->path($key));
    }

    private function path(string $key): string
    {
        return $this->directory . '/' . hash('sha256', $key) . '.json';
    }
}
