<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth;

/** The claims of a token that passed every check, with typed accessors for the ones that drive decisions. */
final class VerifiedToken
{
    /** @param array<string, mixed> $claims */
    public function __construct(public readonly array $claims)
    {
    }

    public function uid(): string
    {
        return (string) $this->claims['sub'];
    }

    public function email(): string
    {
        return strtolower((string) ($this->claims['email'] ?? ''));
    }

    public function emailVerified(): bool
    {
        return ($this->claims['email_verified'] ?? false) === true;
    }

    /** "google.com", "password", "apple.com", "anonymous", "custom"… */
    public function signInProvider(): string
    {
        $firebase = (array) ($this->claims['firebase'] ?? []);
        return (string) ($firebase['sign_in_provider'] ?? '');
    }

    public function isAnonymous(): bool
    {
        return $this->signInProvider() === 'anonymous';
    }

    public function authTime(): ?int
    {
        return isset($this->claims['auth_time']) ? (int) $this->claims['auth_time'] : null;
    }
}
