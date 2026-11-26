<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Keys;

use Showcase\FirebaseAuth\Cache\Cache;
use Showcase\FirebaseAuth\Http\Fetcher;

/**
 * Google's public certificates for Firebase ID tokens, cached for as long as Google says (`Cache-Control: max-age`).
 *
 * Google rotates these keys every few hours and publishes the next one in advance, so honouring max-age means one
 * HTTP call every few hours per cache, not one per request.
 */
final class GoogleCertificateSource implements PublicKeySource
{
    public const URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    private const CACHE_KEY = 'firebase-auth:securetoken-certs';
    private const MIN_TTL = 60;
    private const FALLBACK_TTL = 3600;

    /** Never hit Google more than once per this many seconds on forced refreshes (unknown kid spam). */
    private const REFRESH_COOLDOWN = 30;
    private ?int $lastForcedRefresh = null;

    public function __construct(
        private Fetcher $http,
        private Cache $cache,
        private string $url = self::URL,
    ) {
    }

    public function keys(bool $refresh = false): array
    {
        if (!$refresh || $this->inCooldown()) {
            $cached = $this->cache->get(self::CACHE_KEY);
            if (is_array($cached) && $cached !== []) {
                return $cached;
            }
        }
        if ($refresh) {
            $this->lastForcedRefresh = time();
        }

        $response = $this->http->get($this->url);
        if ($response['status'] !== 200) {
            throw new \RuntimeException("Firebase certificates: HTTP {$response['status']}");
        }
        $certs = json_decode($response['body'], true);
        if (!is_array($certs) || $certs === []) {
            throw new \RuntimeException('Firebase certificates: unexpected body');
        }

        $this->cache->set(self::CACHE_KEY, $certs, self::ttl($response['headers']['cache-control'] ?? ''));
        return $certs;
    }

    /** max-age from a Cache-Control header, floored so a bad header cannot make us call Google on every request. */
    public static function ttl(string $cacheControl): int
    {
        if (preg_match('/max-age=(\d+)/i', $cacheControl, $m)) {
            return max(self::MIN_TTL, (int) $m[1]);
        }
        return self::FALLBACK_TTL;
    }

    private function inCooldown(): bool
    {
        return $this->lastForcedRefresh !== null && time() - $this->lastForcedRefresh < self::REFRESH_COOLDOWN;
    }
}
