<?php

/**
 * Framework-free usage. Run:  php examples/plain-php.php <project-id> <id-token>
 *
 * Get a real token from your web app with `await firebase.auth().currentUser.getIdToken()`.
 */

require __DIR__ . '/../vendor/autoload.php';

use Showcase\FirebaseAuth\Cache\FileCache;
use Showcase\FirebaseAuth\Http\StreamFetcher;
use Showcase\FirebaseAuth\IdTokenVerifier;
use Showcase\FirebaseAuth\InvalidToken;
use Showcase\FirebaseAuth\Keys\GoogleCertificateSource;

[$_, $project, $token] = $argv + [null, '', ''];
if ($project === '' || $token === '') {
    fwrite(STDERR, "usage: php examples/plain-php.php <project-id> <id-token>\n");
    exit(2);
}

$verifier = new IdTokenVerifier(
    $project,
    new GoogleCertificateSource(new StreamFetcher(), new FileCache(sys_get_temp_dir() . '/firebase-certs')),
);

try {
    $user = $verifier->verify($token);
    printf("uid=%s email=%s verified=%s provider=%s\n", $user->uid(), $user->email(), $user->emailVerified() ? 'yes' : 'no', $user->signInProvider());
} catch (InvalidToken $e) {
    fwrite(STDERR, "rejected: {$e->reason}\n");
    exit(1);
}
