<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Showcase\FirebaseAuth\Keys\PublicKeySource;

/**
 * Verifies a Firebase Auth ID token exactly as https://firebase.google.com/docs/auth/admin/verify-id-tokens asks,
 * without pulling in the whole Admin SDK:
 *
 *   header   alg = RS256, kid = one of Google's current keys (unknown kid → refetch once: keys rotate)
 *   payload  exp in the future, iat and auth_time in the past, aud = project id,
 *            iss = https://securetoken.google.com/<project id>, sub non-empty (≤ 128 chars)
 *   sig      valid for the public key named by kid
 *
 * A token that fails any check throws InvalidToken with a stable reason code.
 */
final class IdTokenVerifier
{
    /**
     * @param \Closure(): int|null $clock for tests; defaults to time()
     */
    public function __construct(
        private string $projectId,
        private PublicKeySource $keys,
        private int $leewaySeconds = 60,
        private ?\Closure $clock = null,
    ) {
        if ($projectId === '') {
            throw new \InvalidArgumentException('projectId is required');
        }
    }

    public function verify(string $token): VerifiedToken
    {
        $kid = $this->checkHeader($token);

        $keys = $this->keys->keys();
        if (!isset($keys[$kid])) {
            $keys = $this->keys->keys(refresh: true);
            if (!isset($keys[$kid])) {
                throw new InvalidToken('unknown_kid');
            }
        }

        $now = $this->now();
        // php-jwt reads the clock and the leeway from statics; restore them so we never leak state to other callers.
        [$prevLeeway, $prevTimestamp] = [JWT::$leeway, JWT::$timestamp];
        JWT::$leeway = $this->leewaySeconds;
        JWT::$timestamp = $now;
        try {
            // Only the key named by kid, pinned to RS256: an attacker cannot pick the algorithm or the key.
            $claims = json_decode(json_encode(JWT::decode($token, new Key($keys[$kid], 'RS256'))), true);
        } catch (ExpiredException $e) {
            throw new InvalidToken('expired', previous: $e);
        } catch (BeforeValidException $e) {
            throw new InvalidToken('not_yet_valid', previous: $e);
        } catch (SignatureInvalidException $e) {
            throw new InvalidToken('bad_signature', previous: $e);
        } catch (\UnexpectedValueException | \DomainException $e) {
            throw new InvalidToken('malformed', previous: $e);
        } finally {
            [JWT::$leeway, JWT::$timestamp] = [$prevLeeway, $prevTimestamp];
        }

        $this->checkClaims($claims, $now);

        return new VerifiedToken($claims);
    }

    /** Returns the kid. Cheap checks first: no network for obvious garbage. */
    private function checkHeader(string $token): string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidToken('malformed');
        }
        try {
            $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true, 4, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw new InvalidToken('malformed', previous: $e);
        }
        if (($header['alg'] ?? '') !== 'RS256') {
            throw new InvalidToken('bad_algorithm');   // rejects "none" and HS256-with-the-public-key tricks
        }
        if (!is_string($header['kid'] ?? null) || $header['kid'] === '') {
            throw new InvalidToken('missing_kid');
        }
        return $header['kid'];
    }

    /** @param array<string, mixed> $claims */
    private function checkClaims(array $claims, int $now): void
    {
        if (($claims['aud'] ?? null) !== $this->projectId) {
            throw new InvalidToken('bad_audience');
        }
        if (($claims['iss'] ?? null) !== 'https://securetoken.google.com/' . $this->projectId) {
            throw new InvalidToken('bad_issuer');
        }
        $sub = $claims['sub'] ?? null;
        if (!is_string($sub) || $sub === '' || strlen($sub) > 128) {
            throw new InvalidToken('bad_subject');
        }
        if (!isset($claims['exp'], $claims['iat'])) {
            throw new InvalidToken('missing_times');   // php-jwt treats exp as optional; Firebase does not
        }
        if (isset($claims['auth_time']) && (int) $claims['auth_time'] > $now + $this->leewaySeconds) {
            throw new InvalidToken('bad_auth_time');
        }
    }

    private function now(): int
    {
        return $this->clock ? ($this->clock)() : time();
    }
}
