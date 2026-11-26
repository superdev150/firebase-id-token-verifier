<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Tests;

use PHPUnit\Framework\TestCase;
use Showcase\FirebaseAuth\Access\AdminGate;
use Showcase\FirebaseAuth\IdTokenVerifier;
use Showcase\FirebaseAuth\Keys\PublicKeySource;

final class AdminGateTest extends TestCase
{
    /** @var list<array{string, ?string}> */
    private array $audit = [];

    private function gate(array $providers = ['google.com'], ?PublicKeySource $keys = null): AdminGate
    {
        $verifier = new IdTokenVerifier(TokenFactory::PROJECT, $keys ?? new TokenFactory(), 60, fn () => TokenFactory::NOW);
        return new AdminGate(
            $verifier,
            AdminGate::parseList(' Admin@Example.com , ops@example.com '),
            $providers,
            function (string $reason, ?string $email) {
                $this->audit[] = [$reason, $email];
            },
        );
    }

    public function testLetsAnAllowListedVerifiedGoogleUserIn(): void
    {
        $decision = $this->gate()->check('Bearer ' . TokenFactory::token());

        self::assertTrue($decision->allowed);
        self::assertSame('uid-123', $decision->token?->uid());
        self::assertSame([], $this->audit);
    }

    public function testMatchesEmailsCaseInsensitively(): void
    {
        self::assertTrue($this->gate()->check('Bearer ' . TokenFactory::token(['email' => 'OPS@example.com']))->allowed);
    }

    public function testNoHeaderIs401(): void
    {
        $d = $this->gate()->check(null);
        self::assertSame([401, 'unauthenticated'], [$d->status, $d->code]);

        $d = $this->gate()->check('Basic abc');
        self::assertSame([401, 'unauthenticated'], [$d->status, $d->code]);
    }

    public function testBadTokenIs401AndTheAuditGetsTheReason(): void
    {
        $d = $this->gate()->check('Bearer ' . TokenFactory::token(['exp' => TokenFactory::NOW - 3600]));

        self::assertSame([401, 'invalid_token'], [$d->status, $d->code]);
        self::assertSame([['expired', null]], $this->audit);
    }

    public function testValidTokenOfAStrangerIs403(): void
    {
        $d = $this->gate()->check('Bearer ' . TokenFactory::token(['email' => 'user@gmail.com']));
        self::assertSame([403, 'not_admin'], [$d->status, $d->code]);
    }

    public function testStrangerWithUnverifiedEmailStillGetsNotAdmin(): void
    {
        $d = $this->gate()->check('Bearer ' . TokenFactory::token(['email' => 'user@gmail.com', 'email_verified' => false]));
        self::assertSame('not_admin', $d->code);
    }

    public function testUnverifiedAllowListedAddressIs403(): void
    {
        // Someone registered admin@example.com with a password before the real owner did
        $d = $this->gate([])->check('Bearer ' . TokenFactory::token([
            'email_verified' => false,
            'firebase' => ['sign_in_provider' => 'password'],
        ]));
        self::assertSame([403, 'email_unverified'], [$d->status, $d->code]);
    }

    public function testPasswordSessionIsRefusedWhenOnlyGoogleIsAllowed(): void
    {
        $d = $this->gate()->check('Bearer ' . TokenFactory::token(['firebase' => ['sign_in_provider' => 'password']]));
        self::assertSame([403, 'provider_not_allowed'], [$d->status, $d->code]);
    }

    public function testCertificateOutageFailsClosedWith503(): void
    {
        $down = new class implements PublicKeySource {
            public function keys(bool $refresh = false): array
            {
                throw new \RuntimeException('network down');
            }
        };
        $d = $this->gate(keys: $down)->check('Bearer ' . TokenFactory::token());
        self::assertSame([503, 'auth_unavailable'], [$d->status, $d->code]);
    }
}
