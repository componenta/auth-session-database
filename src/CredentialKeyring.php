<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

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
        $id = $keyId ?? $this->currentKeyId;
        $key = $this->keys[$id]
            ?? throw new \InvalidArgumentException(
                'Unknown session credential key ID.',
            );

        return hash_hmac(
            'sha256',
            "componenta-auth-session-v1\0" . $credential->toString(),
            $key,
        );
    }

    /** @return non-empty-array<string, string> */
    public function candidates(
        #[\SensitiveParameter]
        SessionCredential $credential,
    ): array {
        $result = [];

        foreach (array_keys($this->keys) as $id) {
            $result[$id] = $this->hash($credential, $id);
        }

        return $result;
    }
}
