<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Http;

interface Fetcher
{
    /**
     * GET a URL.
     *
     * @return array{status: int, headers: array<string, string>, body: string} header names in lower case
     */
    public function get(string $url): array;
}
