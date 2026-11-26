<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Tests;

use Firebase\JWT\JWT;
use Showcase\FirebaseAuth\Keys\PublicKeySource;

/**
 * Plays Google in tests: makes RSA keys with self-signed X.509 certificates (the format Google publishes) and signs
 * Firebase-shaped tokens with them. Nothing leaves the process.
 */
final class TokenFactory implements PublicKeySource
{
    public const PROJECT = 'demo-project';
    public const NOW = 1_800_000_000;

    /** @var array<string, array{private: string, cert: string}> */
    private static array $pairs = [];

    /** @var list<string> kids currently "published" */
    public array $published = ['key-1'];
    public int $fetches = 0;
    public int $forcedFetches = 0;

    public static function pair(string $kid): array
    {
        if (!isset(self::$pairs[$kid])) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($key, $private);
            $csr = openssl_csr_new(['commonName' => $kid], $key, ['digest_alg' => 'sha256']);
            $x509 = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
            openssl_x509_export($x509, $cert);
            self::$pairs[$kid] = ['private' => $private, 'cert' => $cert];
        }
        return self::$pairs[$kid];
    }

    public function keys(bool $refresh = false): array
    {
        $this->fetches++;
        if ($refresh) {
            $this->forcedFetches++;
        }
        $out = [];
        foreach ($this->published as $kid) {
            $out[$kid] = self::pair($kid)['cert'];
        }
        return $out;
    }

    /** A token that passes every check, with overrides. */
    public static function token(array $claims = [], string $kid = 'key-1', ?array $header = null): string
    {
        $base = [
            'iss' => 'https://securetoken.google.com/' . self::PROJECT,
            'aud' => self::PROJECT,
            'auth_time' => self::NOW - 600,
            'user_id' => 'uid-123',
            'sub' => 'uid-123',
            'iat' => self::NOW - 60,
            'exp' => self::NOW + 3540,
            'email' => 'admin@example.com',
            'email_verified' => true,
            'firebase' => ['identities' => ['google.com' => ['1']], 'sign_in_provider' => 'google.com'],
        ];
        $payload = array_filter(array_merge($base, $claims), fn ($v) => $v !== null);

        return JWT::encode($payload, self::pair($kid)['private'], 'RS256', $kid, $header);
    }

    /** Re-encode the header of a token (signature left as is). */
    public static function withHeader(string $token, array $header): string
    {
        $parts = explode('.', $token);
        $parts[0] = JWT::urlsafeB64Encode((string) json_encode($header));
        return implode('.', $parts);
    }
}
