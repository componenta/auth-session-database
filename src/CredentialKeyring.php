<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\SessionCredential;

final readonly class CredentialKeyring
{
    private const int MIN_KEY_BYTES = 32;
    private const int MAX_KEY_BYTES = 4096;

    /** @var non-empty-array<string, string> */
    private array $keys;

    /**
     * @param non-empty-array<string, string> $keys
     */
    public function __construct(
        public string $currentKeyId,
        array $keys,
    ) {
        if (!array_key_exists($this->currentKeyId, $keys)) {
            throw new \InvalidArgumentException(
                'Current session credential key must exist in the keyring.',
            );
        }

        foreach ($keys as $id => $key) {
            if (
                preg_match('/\A[a-zA-Z0-9._-]{1,64}\z/D', $id) !== 1
                || strlen($key) < self::MIN_KEY_BYTES
                || strlen($key) > self::MAX_KEY_BYTES
            ) {
                throw new \InvalidArgumentException(
                    'Session credential keyring contains an invalid key.',
                );
            }
        }

        $this->keys = $keys;
    }

    public function hash(
        #[\SensitiveParameter]
        SessionCredential $credential,
        ?string $keyId = null,
    ): string {
        return $this->hashValue(
            'componenta-auth-session-v1',
            $credential->toString(),
            $keyId,
        );
    }

    /** @return non-empty-array<string, string> */
    public function candidates(
        #[\SensitiveParameter]
        SessionCredential $credential,
    ): array {
        return $this->candidateValues(
            'componenta-auth-session-v1',
            $credential->toString(),
        );
    }

    public function hashPreAuthenticationCredential(
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
        ?string $keyId = null,
    ): string {
        return $this->hashValue(
            'componenta-auth-pre-auth-credential-v1',
            $credential->toString(),
            $keyId,
        );
    }

    /** @return non-empty-array<string, string> */
    public function preAuthenticationCredentialCandidates(
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
    ): array {
        return $this->candidateValues(
            'componenta-auth-pre-auth-credential-v1',
            $credential->toString(),
        );
    }

    public function hashPreAuthenticationRequestToken(
        #[\SensitiveParameter]
        PreAuthenticationRequestToken $token,
        ?string $keyId = null,
    ): string {
        return $this->hashValue(
            'componenta-auth-pre-auth-request-token-v1',
            $token->toString(),
            $keyId,
        );
    }

    /** @return non-empty-array<string, string> */
    public function preAuthenticationRequestTokenCandidates(
        #[\SensitiveParameter]
        PreAuthenticationRequestToken $token,
    ): array {
        return $this->candidateValues(
            'componenta-auth-pre-auth-request-token-v1',
            $token->toString(),
        );
    }

    private function hashValue(
        string $domain,
        #[\SensitiveParameter]
        string $value,
        ?string $keyId,
    ): string {
        $id = $keyId ?? $this->currentKeyId;
        $key = $this->keys[$id]
            ?? throw new \InvalidArgumentException(
                'Unknown session credential key ID.',
            );

        return hash_hmac('sha256', $domain . "\0" . $value, $key);
    }

    /** @return non-empty-array<string, string> */
    private function candidateValues(
        string $domain,
        #[\SensitiveParameter]
        string $value,
    ): array {
        $result = [];

        foreach (array_keys($this->keys) as $id) {
            $result[$id] = $this->hashValue($domain, $value, $id);
        }

        /** @var non-empty-array<string, string> $result */
        return $result;
    }
}
