<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Access;

use Showcase\FirebaseAuth\IdTokenVerifier;
use Showcase\FirebaseAuth\InvalidToken;

/**
 * Who may open an admin panel that shares its Firebase project with public apps.
 *
 * A valid token is not enough there: anyone who installs the app has an account in the same project. So the gate also
 * asks for:
 *
 *  1. an e-mail on an allow-list;
 *  2. `email_verified` — otherwise someone could sign up with an allow-listed address that has no account yet
 *     (password providers do not prove ownership of the address);
 *  3. a sign-in provider you trust (e.g. only "google.com") — a leaked password is then useless, and the panel inherits
 *     the 2-step verification of the Google account.
 *
 * Responses: 401 unauthenticated | invalid_token, 403 not_admin | email_unverified | provider_not_allowed.
 * The client can react to each code (e.g. send the verification e-mail on `email_unverified`).
 */
final class AdminGate
{
    /** @var list<string> */
    private array $emails;

    /**
     * @param list<string> $allowedEmails
     * @param list<string> $allowedProviders empty = any provider
     * @param (\Closure(string $reason, ?string $email): void)|null $onDeny audit hook (never receives the token)
     */
    public function __construct(
        private IdTokenVerifier $verifier,
        array $allowedEmails,
        private array $allowedProviders = ['google.com'],
        private ?\Closure $onDeny = null,
    ) {
        $this->emails = array_values(array_filter(array_map(fn ($e) => strtolower(trim($e)), $allowedEmails)));
    }

    /** "a@x.com, B@y.com" → ['a@x.com', 'b@y.com'] (handy for an env var). */
    public static function parseList(string $csv): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $csv))));
    }

    public function check(?string $authorizationHeader): Decision
    {
        if (!preg_match('/^Bearer\s+(\S+)$/i', (string) $authorizationHeader, $m)) {
            return $this->deny(401, 'unauthenticated');
        }

        try {
            $token = $this->verifier->verify($m[1]);
        } catch (InvalidToken $e) {
            return $this->deny(401, 'invalid_token', null, $e->reason);
        } catch (\RuntimeException $e) {
            // Could not reach Google for the certificates: fail closed, but do not blame the user's token.
            return $this->deny(503, 'auth_unavailable');
        }

        $email = $token->email();
        // Order matters: do not tell a stranger whether their address is verified.
        if ($email === '' || !in_array($email, $this->emails, true)) {
            return $this->deny(403, 'not_admin', $token);
        }
        if (!$token->emailVerified()) {
            return $this->deny(403, 'email_unverified', $token);
        }
        if ($this->allowedProviders !== [] && !in_array($token->signInProvider(), $this->allowedProviders, true)) {
            return $this->deny(403, 'provider_not_allowed', $token);
        }

        return Decision::allow($token);
    }

    private function deny(int $status, string $code, ?\Showcase\FirebaseAuth\VerifiedToken $token = null, ?string $detail = null): Decision
    {
        if ($this->onDeny) {
            ($this->onDeny)($detail ?? $code, $token?->email());
        }
        return Decision::deny($status, $code, $token);
    }
}
