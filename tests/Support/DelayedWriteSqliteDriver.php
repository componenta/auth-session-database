<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests\Support;

use Cycle\Database\Driver\SQLite\SQLiteDriver;

/** Pauses one UPDATE before SQLite executes it; transaction control is unaffected. */
final class DelayedWriteSqliteDriver extends SQLiteDriver
{
    /** @var (\Closure(): void)|null */
    public ?\Closure $beforeNextUpdate = null;

    #[\Override]
    public function execute(string $query, array $parameters = []): int
    {
        if (str_starts_with(ltrim($query), 'UPDATE')) {
            $delay = $this->beforeNextUpdate;
            $this->beforeNextUpdate = null;
            $delay?->__invoke();
        }

        return parent::execute($query, $parameters);
    }
}
