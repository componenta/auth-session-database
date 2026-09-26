<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionRegistryInterface;
use Componenta\Auth\Session\ConcurrentSessionOverflow;
use Componenta\Auth\Session\Exception\ConcurrentSessionLimitExceeded;
use Componenta\Auth\Session\Exception\ConcurrentSessionRotationException;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactoryInterface;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\OnConflict;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final readonly class DatabaseAuthSessionManager implements
    AuthSessionManagerInterface,
    AuthSessionRegistryInterface
{
    public function __construct(
        private DatabaseInterface $database,
        private UuidFactoryInterface $uuids,
        private ClockInterface $clock,
        private CredentialKeyring $keyring,
        private DatabaseAuthSessionConfig $config = new DatabaseAuthSessionConfig(),
    ) {}

    #[\Override]
    public function create(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
        AuthSessionPolicy $policy,
        array $metadata = [],
    ): AuthSessionGrant {
        return $this->database->transaction(function () use (
            $subjectId,
            $evidence,
            $policy,
            $metadata,
        ): AuthSessionGrant {
            $this->acquireSubjectLock($subjectId);
            $now = $this->now();
            $active = $this->activeRows($subjectId, $now);

            if (
                $policy->maximumConcurrentSessions !== null
                && count($active) >= $policy->maximumConcurrentSessions
            ) {
                if ($policy->overflow === ConcurrentSessionOverflow::RejectNew) {
                    throw new ConcurrentSessionLimitExceeded(
                        'Maximum concurrent authentication sessions reached.',
                    );
                }

                $revoke = count($active) - $policy->maximumConcurrentSessions + 1;

                foreach (array_slice($active, 0, $revoke) as $row) {
                    $this->revokeUuid(
                        self::stringValue($row, 'uuid'),
                        RevocationReason::Superseded,
                        $now,
                    );
                }
            }

            $uuid = $this->uuids->generate();
            $credential = SessionCredential::generate();
            $keyId = $this->keyring->currentKeyId;
            $credentialHash = $this->keyring->hash($credential);
            $absoluteExpiresAt = $now->modify(
                sprintf('+%d seconds', $policy->absoluteTimeout),
            );
            $idleExpiresAt = $now->modify(
                sprintf('+%d seconds', $policy->idleTimeout),
            );

            if ($idleExpiresAt > $absoluteExpiresAt) {
                $idleExpiresAt = $absoluteExpiresAt;
            }

            $this->database->insert($this->config->sessionTable)->values([
                'uuid' => $uuid->toString(),
                'subject_uuid' => $subjectId->toString(),
                'credential_hash' => $credentialHash,
                'credential_key_id' => $keyId,
                'credential_generation' => 1,
                'created_at' => $this->format($now),
                'authenticated_at' => $this->format($now),
                'reauthenticated_at' => null,
                'last_active_at' => $this->format($now),
                'idle_expires_at' => $this->format($idleExpiresAt),
                'absolute_expires_at' => $this->format($absoluteExpiresAt),
                'evidence' => self::encodeEvidence($evidence),
                'metadata' => self::encodeMetadata($metadata),
                'revoked_at' => null,
                'revocation_reason' => null,
            ])->run();

            return new AuthSessionGrant(
                new AuthSession(
                    $uuid,
                    $subjectId,
                    $evidence,
                    1,
                    $now,
                    $now,
                    null,
                    $now,
                    $idleExpiresAt,
                    $absoluteExpiresAt,
                    $metadata,
                ),
                $credential,
            );
        });
    }

    #[\Override]
    public function resume(
        #[\SensitiveParameter]
        SessionCredential $credential,
    ): ?AuthSession {
        $row = $this->findByCredential($credential);

        if ($row === null) {
            return null;
        }

        $now = $this->now();

        if (!$this->isActiveRow($row, $now)) {
            $this->revokeUuid(
                self::stringValue($row, 'uuid'),
                RevocationReason::Expired,
                $now,
            );

            return null;
        }

        return $this->hydrate($row);
    }

    #[\Override]
    public function touch(AuthSession $observed): void
    {
        $now = $this->now();

        if (
            $observed->idleExpiresAt <= $now
            || $observed->absoluteExpiresAt <= $now
        ) {
            return;
        }

        $idleWindow = max(
            1,
            $observed->idleExpiresAt->getTimestamp()
                - $observed->lastActiveAt->getTimestamp(),
        );
        $idleExpiresAt = $now->modify(sprintf('+%d seconds', $idleWindow));

        if ($idleExpiresAt > $observed->absoluteExpiresAt) {
            $idleExpiresAt = $observed->absoluteExpiresAt;
        }

        $this->database->update($this->config->sessionTable)
            ->where('uuid', $observed->uuid->toString())
            ->where('credential_generation', $observed->credentialGeneration)
            ->where('last_active_at', $this->format($observed->lastActiveAt))
            ->where('revoked_at', null)
            ->where('idle_expires_at', '>', $this->format($now))
            ->where('absolute_expires_at', '>', $this->format($now))
            ->values([
                'last_active_at' => $this->format($now),
                'idle_expires_at' => $this->format($idleExpiresAt),
            ])
            ->run();
    }

    #[\Override]
    public function rotate(
        AuthSession $observed,
        AuthenticationEvidence $evidence,
        RotationReason $reason,
        ?AuthSessionPolicy $policy = null,
    ): AuthSessionGrant {
        return $this->database->transaction(function () use (
            $observed,
            $evidence,
            $reason,
            $policy,
        ): AuthSessionGrant {
            $row = $this->rowByUuid($observed->uuid);

            if ($row === null || !$this->isActiveRow($row, $this->now())) {
                throw new \InvalidArgumentException(
                    'Authentication session is unavailable.',
                );
            }

            $generation = self::intValue($row, 'credential_generation');

            if ($generation !== $observed->credentialGeneration) {
                throw new ConcurrentSessionRotationException(
                    'Authentication session generation changed concurrently.',
                );
            }

            $now = $this->now();
            $oldHash = self::stringValue($row, 'credential_hash');
            $oldKeyId = self::stringValue($row, 'credential_key_id');

            $this->database->insert($this->config->tombstoneTable)->values([
                'credential_hash' => $oldHash,
                'credential_key_id' => $oldKeyId,
                'session_uuid' => $observed->uuid->toString(),
                'replaced_generation' => $generation,
                'expires_at' => $this->format(
                    $now->modify(sprintf('+%d seconds', $this->config->tombstoneTtl)),
                ),
            ])->onConflict(
                OnConflict::target('credential_hash')->doNothing(),
            )->run();

            $credential = SessionCredential::generate();
            $keyId = $this->keyring->currentKeyId;
            $newHash = $this->keyring->hash($credential);
            $absoluteExpiresAt = $this->date(
                self::stringValue($row, 'absolute_expires_at'),
            );
            $idleWindow = $policy !== null
                ? $policy->idleTimeout
                : max(
                    1,
                    $this->date(self::stringValue($row, 'idle_expires_at'))->getTimestamp()
                        - $this->date(self::stringValue($row, 'last_active_at'))->getTimestamp(),
                );

            if ($policy !== null) {
                $policyAbsolute = $now->modify(
                    sprintf('+%d seconds', $policy->absoluteTimeout),
                );

                if ($policyAbsolute < $absoluteExpiresAt) {
                    $absoluteExpiresAt = $policyAbsolute;
                }
            }

            $idleExpiresAt = $now->modify(sprintf('+%d seconds', $idleWindow));

            if ($idleExpiresAt > $absoluteExpiresAt) {
                $idleExpiresAt = $absoluteExpiresAt;
            }

            $reauthenticatedAt = $reason === RotationReason::Reauthentication
                ? $now
                : self::nullableDate($row['reauthenticated_at'] ?? null);

            $affected = $this->database->update($this->config->sessionTable)
                ->where('uuid', $observed->uuid->toString())
                ->where('credential_generation', $generation)
                ->where('credential_hash', $oldHash)
                ->where('revoked_at', null)
                ->values([
                    'credential_hash' => $newHash,
                    'credential_key_id' => $keyId,
                    'credential_generation' => $generation + 1,
                    'evidence' => self::encodeEvidence($evidence),
                    'reauthenticated_at' => $reauthenticatedAt === null
                        ? null
                        : $this->format($reauthenticatedAt),
                    'last_active_at' => $this->format($now),
                    'idle_expires_at' => $this->format($idleExpiresAt),
                    'absolute_expires_at' => $this->format($absoluteExpiresAt),
                ])
                ->run();

            if ($affected !== 1) {
                throw new ConcurrentSessionRotationException(
                    'Authentication session rotated or revoked concurrently.',
                );
            }

            return new AuthSessionGrant(
                new AuthSession(
                    $observed->uuid,
                    $observed->subjectId,
                    $evidence,
                    $generation + 1,
                    $this->date(self::stringValue($row, 'created_at')),
                    $this->date(self::stringValue($row, 'authenticated_at')),
                    $reauthenticatedAt,
                    $now,
                    $idleExpiresAt,
                    $absoluteExpiresAt,
                    self::decodeMetadata(self::stringValue($row, 'metadata')),
                ),
                $credential,
            );
        });
    }

    #[\Override]
    public function revoke(
        UuidInterface $sessionId,
        RevocationReason $reason,
    ): void {
        $this->revokeUuid($sessionId->toString(), $reason, $this->now());
    }

    #[\Override]
    public function revokePresentedCredential(
        #[\SensitiveParameter]
        SessionCredential $credential,
        RevocationReason $reason,
    ): void {
        $row = $this->findByCredential($credential);

        if ($row !== null) {
            $this->revokeUuid(
                self::stringValue($row, 'uuid'),
                $reason,
                $this->now(),
            );

            return;
        }

        $hashes = array_values($this->keyring->candidates($credential));
        $row = $this->database->select(['session_uuid', 'expires_at'])
            ->from($this->config->tombstoneTable)
            ->where('credential_hash', 'IN', $hashes)
            ->run()
            ->fetch();

        if (
            is_array($row)
            && $this->date(self::stringValue($row, 'expires_at')) > $this->now()
        ) {
            $this->revokeUuid(
                self::stringValue($row, 'session_uuid'),
                $reason,
                $this->now(),
            );
        }
    }

    #[\Override]
    public function revokeAll(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
        RevocationReason $reason = RevocationReason::UserRequested,
    ): void {
        $this->database->transaction(function () use (
            $subjectId,
            $exceptSessionId,
            $reason,
        ): void {
            $this->acquireSubjectLock($subjectId);
            $query = $this->database->update($this->config->sessionTable)
                ->where('subject_uuid', $subjectId->toString())
                ->where('revoked_at', null);

            if ($exceptSessionId !== null) {
                $query->where('uuid', '!=', $exceptSessionId->toString());
            }

            $now = $this->now();

            $query->values([
                'revoked_at' => $this->format($now),
                'revocation_reason' => $reason->value,
            ])->run();
        });
    }

    #[\Override]
    public function isGrantCurrent(AuthSessionGrant $grant): bool
    {
        $row = $this->rowByUuid($grant->session->uuid);

        if (
            $row === null
            || !$this->isActiveRow($row, $this->now())
            || self::intValue($row, 'credential_generation')
                !== $grant->session->credentialGeneration
        ) {
            return false;
        }

        $keyId = self::stringValue($row, 'credential_key_id');

        try {
            $expected = $this->keyring->hash($grant->credential, $keyId);
        } catch (\InvalidArgumentException) {
            return false;
        }

        return hash_equals(
            self::stringValue($row, 'credential_hash'),
            $expected,
        );
    }

    #[\Override]
    public function find(UuidInterface $sessionId): ?AuthSession
    {
        $row = $this->rowByUuid($sessionId);

        return $row !== null && $this->isActiveRow($row, $this->now())
            ? $this->hydrate($row)
            : null;
    }

    #[\Override]
    public function all(UuidInterface $subjectId): array
    {
        $rows = $this->activeRows($subjectId, $this->now());

        return array_map(
            fn(array $row): AuthSession => $this->hydrate($row),
            $rows,
        );
    }

    private function acquireSubjectLock(UuidInterface $subjectId): void
    {
        $subject = $subjectId->toString();

        $this->database->insert($this->config->subjectLockTable)->values([
            'subject_uuid' => $subject,
            'lock_version' => 0,
        ])->onConflict(
            OnConflict::target('subject_uuid')->doNothing(),
        )->run();

        $affected = $this->database->execute(
            sprintf(
                'UPDATE %s SET lock_version = lock_version + 1 WHERE subject_uuid = ?',
                $this->config->subjectLockTable,
            ),
            [$subject],
        );

        if ($affected !== 1) {
            throw new \RuntimeException(
                'Could not acquire authentication-session subject lock.',
            );
        }
    }

    /** @return list<array<array-key, mixed>> */
    private function activeRows(
        UuidInterface $subjectId,
        DateTimeImmutable $now,
    ): array {
        $rows = $this->database->select()
            ->from($this->config->sessionTable)
            ->where('subject_uuid', $subjectId->toString())
            ->where('revoked_at', null)
            ->where('idle_expires_at', '>', $this->format($now))
            ->where('absolute_expires_at', '>', $this->format($now))
            ->orderBy('created_at', 'ASC')
            ->run()
            ->fetchAll();

        return array_values(array_filter($rows, 'is_array'));
    }

    /** @return array<array-key, mixed>|null */
    private function rowByUuid(UuidInterface $uuid): ?array
    {
        $row = $this->database->select()
            ->from($this->config->sessionTable)
            ->where('uuid', $uuid->toString())
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    /** @return array<array-key, mixed>|null */
    private function findByCredential(
        #[\SensitiveParameter]
        SessionCredential $credential,
    ): ?array {
        $candidates = $this->keyring->candidates($credential);
        $row = $this->database->select()
            ->from($this->config->sessionTable)
            ->where('credential_hash', 'IN', array_values($candidates))
            ->where('revoked_at', null)
            ->run()
            ->fetch();

        if (!is_array($row)) {
            return null;
        }

        $keyId = self::stringValue($row, 'credential_key_id');
        $candidate = $candidates[$keyId] ?? null;

        return is_string($candidate)
            && hash_equals(self::stringValue($row, 'credential_hash'), $candidate)
                ? $row
                : null;
    }

    private function revokeUuid(
        string $uuid,
        RevocationReason $reason,
        DateTimeImmutable $now,
    ): void {
        $this->database->update($this->config->sessionTable)
            ->where('uuid', $uuid)
            ->where('revoked_at', null)
            ->values([
                'revoked_at' => $this->format($now),
                'revocation_reason' => $reason->value,
            ])
            ->run();
    }

    /** @param array<array-key, mixed> $row */
    private function isActiveRow(
        array $row,
        DateTimeImmutable $now,
    ): bool {
        return ($row['revoked_at'] ?? null) === null
            && $this->date(self::stringValue($row, 'idle_expires_at')) > $now
            && $this->date(self::stringValue($row, 'absolute_expires_at')) > $now;
    }

    /** @param array<array-key, mixed> $row */
    private function hydrate(array $row): AuthSession
    {
        return new AuthSession(
            Uuid::fromString(self::stringValue($row, 'uuid')),
            Uuid::fromString(self::stringValue($row, 'subject_uuid')),
            self::decodeEvidence(self::stringValue($row, 'evidence')),
            self::intValue($row, 'credential_generation'),
            $this->date(self::stringValue($row, 'created_at')),
            $this->date(self::stringValue($row, 'authenticated_at')),
            self::nullableDate($row['reauthenticated_at'] ?? null),
            $this->date(self::stringValue($row, 'last_active_at')),
            $this->date(self::stringValue($row, 'idle_expires_at')),
            $this->date(self::stringValue($row, 'absolute_expires_at')),
            self::decodeMetadata(self::stringValue($row, 'metadata')),
        );
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $value): string
    {
        return $value->setTimezone(new DateTimeZone('UTC'))
            ->format(DatabaseAuthSessionConfig::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        return self::parseDatabaseDate(
            $value,
            'Authentication-session timestamp is invalid.',
        );
    }

    private static function nullableDate(mixed $value): ?DateTimeImmutable
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new \UnexpectedValueException(
                'Authentication-session nullable timestamp is invalid.',
            );
        }

        return self::parseDatabaseDate(
            $value,
            'Authentication-session nullable timestamp is invalid.',
        );
    }

    private static function parseDatabaseDate(
        string $value,
        string $error,
    ): DateTimeImmutable {
        $timezone = new DateTimeZone('UTC');

        foreach ([
            '!Y-m-d H:i:s.u',
            '!Y-m-d H:i:s',
        ] as $format) {
            $date = DateTimeImmutable::createFromFormat(
                $format,
                $value,
                $timezone,
            );

            if ($date instanceof DateTimeImmutable) {
                return $date;
            }
        }

        throw new \UnexpectedValueException($error);
    }

    private static function encodeEvidence(AuthenticationEvidence $evidence): string
    {
        return json_encode([
            'methods' => $evidence->methods,
            'capabilities' => $evidence->capabilities,
        ], JSON_THROW_ON_ERROR);
    }

    private static function decodeEvidence(string $json): AuthenticationEvidence
    {
        $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);

        if (
            !is_array($data)
            || !isset($data['methods'])
            || !is_array($data['methods'])
            || !isset($data['capabilities'])
            || !is_array($data['capabilities'])
        ) {
            throw new \UnexpectedValueException(
                'Persisted authentication evidence is invalid.',
            );
        }

        /** @var list<string> $methods */
        $methods = array_values(array_filter($data['methods'], 'is_string'));
        /** @var list<string> $capabilities */
        $capabilities = array_values(array_filter(
            $data['capabilities'],
            'is_string',
        ));

        if (
            $methods === []
            || count($methods) !== count($data['methods'])
            || count($capabilities) !== count($data['capabilities'])
        ) {
            throw new \UnexpectedValueException(
                'Persisted authentication evidence is invalid.',
            );
        }

        /** @var non-empty-list<string> $methods */
        return new AuthenticationEvidence($methods, $capabilities);
    }

    /** @param array<string, mixed> $metadata */
    private static function encodeMetadata(array $metadata): string
    {
        return json_encode($metadata, JSON_THROW_ON_ERROR);
    }

    /** @return array<string, scalar|null> */
    private static function decodeMetadata(string $json): array
    {
        $metadata = json_decode($json, true, 32, JSON_THROW_ON_ERROR);

        if (!is_array($metadata)) {
            throw new \UnexpectedValueException(
                'Persisted authentication-session metadata is invalid.',
            );
        }

        $result = [];

        foreach ($metadata as $key => $value) {
            if (!is_string($key) || (!is_scalar($value) && $value !== null)) {
                throw new \UnexpectedValueException(
                    'Persisted authentication-session metadata is invalid.',
                );
            }

            $result[$key] = $value;
        }

        return $result;
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain a string-compatible value.',
                $key,
            ));
        }

        return (string) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(array $row, string $key): int
    {
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain an integer.',
                $key,
            ));
        }

        return (int) $value;
    }
}
