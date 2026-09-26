<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactoryInterface;
use Cycle\Database\DatabaseInterface;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final readonly class DatabasePreAuthenticationManager implements
    PreAuthenticationManagerInterface
{
    public function __construct(
        private DatabaseInterface $database,
        private UuidFactoryInterface $uuids,
        private ClockInterface $clock,
        private CredentialKeyring $keyring,
        private DatabaseAuthSessionConfig $config = new DatabaseAuthSessionConfig(),
    ) {}

    #[\Override]
    public function create(int $ttlSeconds = 300): PreAuthenticationGrant
    {
        if ($ttlSeconds < 30 || $ttlSeconds > 1800) {
            throw new \InvalidArgumentException(
                'Pre-authentication TTL must be between 30 and 1800 seconds.',
            );
        }

        $now = $this->now();
        $expiresAt = $now->modify(sprintf('+%d seconds', $ttlSeconds));
        $uuid = $this->uuids->generate();
        $credential = PreAuthenticationCredential::generate();
        $requestToken = PreAuthenticationRequestToken::generate();
        $keyId = $this->keyring->currentKeyId;

        $this->database->insert($this->config->preAuthenticationTable)->values([
            'uuid' => $uuid->toString(),
            'credential_hash' => $this->keyring
                ->hashPreAuthenticationCredential($credential),
            'credential_key_id' => $keyId,
            'request_token_hash' => $this->keyring
                ->hashPreAuthenticationRequestToken($requestToken),
            'request_token_key_id' => $keyId,
            'created_at' => $this->format($now),
            'expires_at' => $this->format($expiresAt),
        ])->run();

        return new PreAuthenticationGrant(
            new PreAuthenticationTransaction($uuid, $now, $expiresAt),
            $credential,
            $requestToken,
        );
    }

    #[\Override]
    public function consume(
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
        #[\SensitiveParameter]
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction {
        $credentialCandidates = $this->keyring
            ->preAuthenticationCredentialCandidates($credential);
        $row = $this->database->select()
            ->from($this->config->preAuthenticationTable)
            ->where(
                'credential_hash',
                'IN',
                array_values($credentialCandidates),
            )
            ->run()
            ->fetch();

        if (!is_array($row)) {
            return null;
        }

        $now = $this->now();
        $expiresAt = $this->date(self::stringValue($row, 'expires_at'));

        if ($expiresAt <= $now) {
            $this->deleteRow(self::stringValue($row, 'uuid'));
            return null;
        }

        $credentialKeyId = self::stringValue($row, 'credential_key_id');
        $credentialHash = $credentialCandidates[$credentialKeyId] ?? null;

        if (
            !is_string($credentialHash)
            || !hash_equals(
                self::stringValue($row, 'credential_hash'),
                $credentialHash,
            )
        ) {
            return null;
        }

        $requestKeyId = self::stringValue($row, 'request_token_key_id');

        try {
            $requestHash = $this->keyring->hashPreAuthenticationRequestToken(
                $requestToken,
                $requestKeyId,
            );
        } catch (\InvalidArgumentException) {
            return null;
        }

        if (
            !hash_equals(
                self::stringValue($row, 'request_token_hash'),
                $requestHash,
            )
        ) {
            return null;
        }

        $uuid = self::stringValue($row, 'uuid');
        $affected = $this->database->delete(
            $this->config->preAuthenticationTable,
        )
            ->where('uuid', $uuid)
            ->where('credential_hash', $credentialHash)
            ->where('request_token_hash', $requestHash)
            ->where('expires_at', '>', $this->format($now))
            ->run();

        if ($affected !== 1) {
            return null;
        }

        return new PreAuthenticationTransaction(
            Uuid::fromString($uuid),
            $this->date(self::stringValue($row, 'created_at')),
            $expiresAt,
        );
    }

    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > 10_000) {
            throw new \InvalidArgumentException(
                'Pre-authentication cleanup limit must be between 1 and 10000.',
            );
        }

        $rows = $this->database->select('uuid')
            ->from($this->config->preAuthenticationTable)
            ->where('expires_at', '<=', $this->format($this->now()))
            ->limit($limit)
            ->run()
            ->fetchAll();
        $uuids = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['uuid'] ?? null)) {
                $uuids[] = $row['uuid'];
            }
        }

        return $uuids === []
            ? 0
            : $this->database->delete($this->config->preAuthenticationTable)
                ->where('uuid', 'IN', $uuids)
                ->run();
    }

    private function deleteRow(string $uuid): void
    {
        $this->database->delete($this->config->preAuthenticationTable)
            ->where('uuid', $uuid)
            ->run();
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $date): string
    {
        return $date->setTimezone(new DateTimeZone('UTC'))
            ->format(DatabaseAuthSessionConfig::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        $date = DateTimeImmutable::createFromFormat(
            '!' . DatabaseAuthSessionConfig::DATE_FORMAT,
            $value,
            new DateTimeZone('UTC'),
        );

        if (!$date instanceof DateTimeImmutable) {
            throw new \UnexpectedValueException(
                'Pre-authentication timestamp is invalid.',
            );
        }

        return $date;
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
}
