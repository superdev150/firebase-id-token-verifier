<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Http;

/** Dependency-free HTTP GET with PHP streams. Swap in Guzzle or your framework's client by implementing Fetcher. */
final class StreamFetcher implements Fetcher
{
    public function __construct(private int $timeoutSeconds = 10)
    {
    }

    public function get(string $url): array
    {
        $context = stream_context_create(['http' => [
            'method' => 'GET',
            'timeout' => $this->timeoutSeconds,
            'ignore_errors' => true,
            'header' => "Accept: application/json\r\n",
        ]]);

        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            throw new \RuntimeException("GET {$url} failed");
        }

        // $http_response_header is filled in by the stream wrapper
        $lines = $http_response_header ?? [];
        $status = 0;
        $headers = [];
        foreach ($lines as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];   // the last status line wins (redirects)
                $headers = [];
            } elseif (str_contains($line, ':')) {
                [$name, $value] = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        return ['status' => $status, 'headers' => $headers, 'body' => $body];
    }
}
