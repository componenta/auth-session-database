<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

use Cycle\Database\DatabaseInterface;
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
        $deleted = $this->database->delete($this->config->tombstoneTable)
            ->where('expires_at', '<=', $now)
            ->limit($limit)
            ->run();

        if ($deleted >= $limit) {
            return $deleted;
        }

        $remaining = $limit - $deleted;

        return $deleted + $this->database->delete($this->config->sessionTable)
            ->where(static function (mixed $query) use ($now): void {
                $query->where('revoked_at', '!=', null)
                    ->orWhere('idle_expires_at', '<=', $now)
                    ->orWhere('absolute_expires_at', '<=', $now);
            })
            ->limit($remaining)
            ->run();
    }
}
