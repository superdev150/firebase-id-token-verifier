<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Tests;

use PHPUnit\Framework\TestCase;
use Showcase\FirebaseAuth\Cache\ArrayCache;
use Showcase\FirebaseAuth\Cache\FileCache;
use Showcase\FirebaseAuth\Http\Fetcher;
use Showcase\FirebaseAuth\Keys\GoogleCertificateSource;

final class GoogleCertificateSourceTest extends TestCase
{
    private function fetcher(array $responses): Fetcher
    {
        return new class ($responses) implements Fetcher {
            public int $calls = 0;

            public function __construct(private array $responses)
            {
            }

            public function get(string $url): array
            {
                return $this->responses[min($this->calls++, count($this->responses) - 1)];
            }
        };
    }

    private static function ok(array $certs, string $cacheControl = 'public, max-age=19800, must-revalidate'): array
    {
        return ['status' => 200, 'headers' => ['cache-control' => $cacheControl], 'body' => json_encode($certs)];
    }

    public function testCachesForMaxAge(): void
    {
        $now = 1000;
        $http = $this->fetcher([self::ok(['a' => 'PEM-A'], 'max-age=600')]);
        $source = new GoogleCertificateSource($http, new ArrayCache(function () use (&$now) {
            return $now;
        }));

        self::assertSame(['a' => 'PEM-A'], $source->keys());
        $now += 599;
        $source->keys();
        self::assertSame(1, $http->calls);

        $now += 2;
        $source->keys();
        self::assertSame(2, $http->calls);
    }

    public function testTtlParsing(): void
    {
        self::assertSame(19800, GoogleCertificateSource::ttl('public, max-age=19800, must-revalidate'));
        self::assertSame(60, GoogleCertificateSource::ttl('max-age=0'));   // floored
        self::assertSame(3600, GoogleCertificateSource::ttl(''));          // fallback
    }

    public function testForcedRefreshesAreRateLimited(): void
    {
        $http = $this->fetcher([self::ok(['a' => 'A']), self::ok(['a' => 'A', 'b' => 'B'])]);
        $source = new GoogleCertificateSource($http, new ArrayCache());

        $source->keys();
        self::assertSame(['a' => 'A', 'b' => 'B'], $source->keys(refresh: true));
        // A flood of tokens with random kids must not turn into a flood of calls to Google
        for ($i = 0; $i < 10; $i++) {
            $source->keys(refresh: true);
        }
        self::assertSame(2, $http->calls);
    }

    public function testHttpErrorsThrow(): void
    {
        $source = new GoogleCertificateSource($this->fetcher([['status' => 500, 'headers' => [], 'body' => '']]), new ArrayCache());
        $this->expectException(\RuntimeException::class);
        $source->keys();
    }

    public function testFileCacheRoundTrip(): void
    {
        $dir = sys_get_temp_dir() . '/fb-verifier-' . bin2hex(random_bytes(4));
        $cache = new FileCache($dir);
        $cache->set('k', ['a' => 'b'], 60);
        self::assertSame(['a' => 'b'], (new FileCache($dir))->get('k'));
        self::assertNull($cache->get('missing'));
        array_map('unlink', glob("{$dir}/*"));
        rmdir($dir);
    }
}
