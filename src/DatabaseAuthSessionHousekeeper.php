<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\SelectQuery;
use Psr\Clock\ClockInterface;

final readonly class DatabaseAuthSessionHousekeeper
{
    public function __construct(
        private DatabaseInterface $database,
        private ClockInterface $clock,
        private DatabaseAuthSessionConfig $config = new DatabaseAuthSessionConfig(),
    ) {}

    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > 10_000) {
            throw new \InvalidArgumentException(
                'Cleanup limit must be between 1 and 10000.',
            );
        }

        $now = $this->clock->now()->format(DatabaseAuthSessionConfig::DATE_FORMAT);
        $tombstones = $this->database->select('credential_hash')
            ->from($this->config->tombstoneTable)
            ->where('expires_at', '<=', $now)
            ->limit($limit)
            ->run()
            ->fetchAll();
        $hashes = [];

        foreach ($tombstones as $row) {
            if (is_array($row) && is_string($row['credential_hash'] ?? null)) {
                $hashes[] = $row['credential_hash'];
            }
        }

        $deleted = $hashes === []
            ? 0
            : $this->database->delete($this->config->tombstoneTable)
                ->where('credential_hash', 'IN', $hashes)
                ->run();

        if ($deleted >= $limit) {
            return $deleted;
        }

        $remaining = $limit - $deleted;
        $query = $this->database->select('uuid');

        $rows = $query->from($this->config->sessionTable)
            ->where(static function (SelectQuery $query) use ($now): void {
                $query->where('revoked_at', '!=', null)
                    ->orWhere('idle_expires_at', '<=', $now)
                    ->orWhere('absolute_expires_at', '<=', $now);
            })
            ->limit($remaining)
            ->run()
            ->fetchAll();
        $uuids = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['uuid'] ?? null)) {
                $uuids[] = $row['uuid'];
            }
        }

        if ($uuids === []) {
            return $deleted;
        }

        return $deleted + $this->database->delete($this->config->sessionTable)
            ->where('uuid', 'IN', $uuids)
            ->run();
    }
}
