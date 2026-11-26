<?php

declare(strict_types=1);

namespace Showcase\FirebaseAuth\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Showcase\FirebaseAuth\IdTokenVerifier;
use Showcase\FirebaseAuth\InvalidToken;

final class IdTokenVerifierTest extends TestCase
{
    private TokenFactory $google;
    private IdTokenVerifier $verifier;

    protected function setUp(): void
    {
        $this->google = new TokenFactory();
        $this->verifier = new IdTokenVerifier(TokenFactory::PROJECT, $this->google, 60, fn () => TokenFactory::NOW);
    }

    public function testAcceptsAValidToken(): void
    {
        $token = $this->verifier->verify(TokenFactory::token());

        self::assertSame('uid-123', $token->uid());
        self::assertSame('admin@example.com', $token->email());
        self::assertTrue($token->emailVerified());
        self::assertSame('google.com', $token->signInProvider());
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function badClaims(): iterable
    {
        yield 'expired' => [['exp' => TokenFactory::NOW - 61], 'expired'];
        yield 'issued in the future' => [['iat' => TokenFactory::NOW + 120], 'not_yet_valid'];
        yield 'other project (aud)' => [['aud' => 'someone-else'], 'bad_audience'];
        yield 'other issuer' => [['iss' => 'https://securetoken.google.com/someone-else'], 'bad_issuer'];
        yield 'empty subject' => [['sub' => ''], 'bad_subject'];
        yield 'subject too long' => [['sub' => str_repeat('a', 129)], 'bad_subject'];
        yield 'auth_time in the future' => [['auth_time' => TokenFactory::NOW + 3600], 'bad_auth_time'];
        yield 'no exp' => [['exp' => null], 'missing_times'];
    }

    #[DataProvider('badClaims')]
    public function testRejectsBadClaims(array $claims, string $reason): void
    {
        $this->assertRejected(TokenFactory::token($claims), $reason);
    }

    public function testToleratesSmallClockSkew(): void
    {
        $token = $this->verifier->verify(TokenFactory::token(['exp' => TokenFactory::NOW - 30]));
        self::assertSame('uid-123', $token->uid());
    }

    public function testRejectsATokenSignedByAnotherKeyUnderAKnownKid(): void
    {
        // Signed with key-2's private key but claims to be key-1
        $forged = JWT::encode(
            json_decode(json_encode(JWT::jsonDecode(JWT::urlsafeB64Decode(explode('.', TokenFactory::token())[1]))), true),
            TokenFactory::pair('key-2')['private'],
            'RS256',
            'key-1',
        );
        $this->assertRejected($forged, 'bad_signature');
    }

    public function testRejectsTamperedPayload(): void
    {
        [$h, , $s] = explode('.', TokenFactory::token());
        $payload = JWT::urlsafeB64Encode((string) json_encode(['sub' => 'attacker'] + [
            'iss' => 'https://securetoken.google.com/' . TokenFactory::PROJECT, 'aud' => TokenFactory::PROJECT,
            'iat' => TokenFactory::NOW, 'exp' => TokenFactory::NOW + 100,
        ]));
        $this->assertRejected("{$h}.{$payload}.{$s}", 'bad_signature');
    }

    public function testRejectsAlgNone(): void
    {
        $this->assertRejected(TokenFactory::withHeader(TokenFactory::token(), ['alg' => 'none', 'kid' => 'key-1']), 'bad_algorithm');
    }

    public function testRejectsHs256EvenWithAKnownKid(): void
    {
        $this->assertRejected(TokenFactory::withHeader(TokenFactory::token(), ['alg' => 'HS256', 'kid' => 'key-1']), 'bad_algorithm');
    }

    public function testRejectsMissingKid(): void
    {
        $this->assertRejected(TokenFactory::withHeader(TokenFactory::token(), ['alg' => 'RS256']), 'missing_kid');
    }

    public function testRejectsGarbageWithoutFetchingKeys(): void
    {
        $this->assertRejected('not-a-jwt', 'malformed');
        $this->assertRejected('a.b.c', 'malformed');
        self::assertSame(0, $this->google->fetches);
    }

    public function testRefetchesOnceWhenGoogleRotatedItsKeys(): void
    {
        $this->google->published = ['key-1'];
        $token = TokenFactory::token(kid: 'key-2');

        // The cached set does not have key-2 yet; after the refresh it does
        $google = $this->google;
        $rotating = new class ($google) implements \Showcase\FirebaseAuth\Keys\PublicKeySource {
            public function __construct(private TokenFactory $inner)
            {
            }

            public function keys(bool $refresh = false): array
            {
                if ($refresh) {
                    $this->inner->published = ['key-1', 'key-2'];
                }
                return $this->inner->keys($refresh);
            }
        };
        $verifier = new IdTokenVerifier(TokenFactory::PROJECT, $rotating, 60, fn () => TokenFactory::NOW);

        self::assertSame('uid-123', $verifier->verify($token)->uid());
        self::assertSame(1, $this->google->forcedFetches);
    }

    public function testUnknownKidAfterRefreshIsRejected(): void
    {
        $this->assertRejected(TokenFactory::token(kid: 'key-9'), 'unknown_kid');
        self::assertSame(1, $this->google->forcedFetches);
    }

    public function testDoesNotLeakPhpJwtGlobals(): void
    {
        JWT::$leeway = 0;
        JWT::$timestamp = null;
        $this->verifier->verify(TokenFactory::token());
        self::assertSame(0, JWT::$leeway);
        self::assertNull(JWT::$timestamp);
    }

    private function assertRejected(string $token, string $reason): void
    {
        try {
            $this->verifier->verify($token);
            self::fail("Expected InvalidToken({$reason})");
        } catch (InvalidToken $e) {
            self::assertSame($reason, $e->reason);
        }
    }
}
