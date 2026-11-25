<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\SessionCredential;
use PHPUnit\Framework\TestCase;

final class CredentialKeyringTest extends TestCase
{
    public function testNumericKeyIdentifiersSupportLookupAndCandidateGeneration(): void
    {
        $keyring = new CredentialKeyring('2', [
            '1' => str_repeat('a', 32),
            '2' => str_repeat('b', 32),
        ]);
        $session = SessionCredential::fromBytes(str_repeat('s', 32));
        $credential = PreAuthenticationCredential::fromBytes(str_repeat('c', 32));
        $requestToken = PreAuthenticationRequestToken::fromBytes(str_repeat('t', 32));

        self::assertSame('2', $keyring->currentKeyId);
        self::assertSame($keyring->hash($session, '2'), $keyring->hash($session));
        self::assertSame([
            '1' => $keyring->hash($session, '1'),
            '2' => $keyring->hash($session, '2'),
        ], $keyring->candidates($session));
        self::assertSame([
            '1' => $keyring->hashPreAuthenticationCredential($credential, '1'),
            '2' => $keyring->hashPreAuthenticationCredential($credential, '2'),
        ], $keyring->preAuthenticationCredentialCandidates($credential));
        self::assertSame([
            '1' => $keyring->hashPreAuthenticationRequestToken($requestToken, '1'),
            '2' => $keyring->hashPreAuthenticationRequestToken($requestToken, '2'),
        ], $keyring->preAuthenticationRequestTokenCandidates($requestToken));
        self::assertNotSame($keyring->hash($session, '1'), $keyring->hash($session, '2'));
    }

    public function testKeyMaterialIsAnOwnedSnapshotAcrossCredentialDomains(): void
    {
        $key = str_repeat('a', 32);
        $keyring = new CredentialKeyring('current', ['current' => &$key]);
        $session = SessionCredential::fromBytes(str_repeat('s', 32));
        $credential = PreAuthenticationCredential::fromBytes(str_repeat('c', 32));
        $requestToken = PreAuthenticationRequestToken::fromBytes(str_repeat('t', 32));
        $sessionHash = $keyring->hash($session);
        $credentialHash = $keyring->hashPreAuthenticationCredential($credential);
        $requestHash = $keyring->hashPreAuthenticationRequestToken($requestToken);

        $key = str_repeat('b', 32);
        $replacement = new CredentialKeyring('current', ['current' => $key]);

        self::assertSame($sessionHash, $keyring->hash($session));
        self::assertSame($credentialHash, $keyring->hashPreAuthenticationCredential($credential));
        self::assertSame($requestHash, $keyring->hashPreAuthenticationRequestToken($requestToken));
        self::assertSame(['current' => $sessionHash], $keyring->candidates($session));
        self::assertSame(['current' => $credentialHash], $keyring->preAuthenticationCredentialCandidates($credential));
        self::assertSame(['current' => $requestHash], $keyring->preAuthenticationRequestTokenCandidates($requestToken));
        self::assertNotSame($sessionHash, $replacement->hash($session));
    }
}
