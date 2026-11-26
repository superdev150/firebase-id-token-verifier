<?php

/**
 * Laravel middleware built on AdminGate. Register it on the admin route group:
 *
 *   Route::middleware(FirebaseAdmin::class)->prefix('admin')->group(...);
 *
 * .env:  FIREBASE_PROJECT_ID=my-project   ADMIN_EMAILS=me@example.com,ops@example.com
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache as LaravelCache;
use Illuminate\Support\Facades\Log;
use Showcase\FirebaseAuth\Access\AdminGate;
use Showcase\FirebaseAuth\Cache\Cache;
use Showcase\FirebaseAuth\Http\StreamFetcher;
use Showcase\FirebaseAuth\IdTokenVerifier;
use Showcase\FirebaseAuth\Keys\GoogleCertificateSource;
use Symfony\Component\HttpFoundation\Response;

final class FirebaseAdmin
{
    public function handle(Request $request, Closure $next): Response
    {
        $decision = $this->gate()->check($request->header('Authorization'));

        if (!$decision->allowed) {
            return response()->json(['code' => $decision->code], $decision->status);
        }

        $request->attributes->set('admin_uid', $decision->token->uid());
        $request->attributes->set('admin_email', $decision->token->email());
        return $next($request);
    }

    private function gate(): AdminGate
    {
        // Laravel's cache (Redis, file…) shared by every PHP-FPM worker
        $cache = new class implements Cache {
            public function get(string $key): mixed
            {
                return LaravelCache::get($key);
            }

            public function set(string $key, mixed $value, int $ttlSeconds): void
            {
                LaravelCache::put($key, $value, $ttlSeconds);
            }
        };

        $verifier = new IdTokenVerifier(
            config('services.firebase.project_id'),
            new GoogleCertificateSource(new StreamFetcher(), $cache),
        );

        return new AdminGate(
            $verifier,
            AdminGate::parseList((string) config('services.admin.emails')),
            allowedProviders: ['google.com'],
            onDeny: fn (string $reason, ?string $email) => Log::warning('admin denied', compact('reason', 'email')),
        );
    }
}
