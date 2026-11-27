<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests\Support;

use Cycle\Database\Config\DatabaseConfig;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\DatabaseManager;
use Cycle\Database\Driver\DriverInterface;

final class SqliteDatabaseFixture
{
    public static function create(?DriverInterface $driver = null): DatabaseInterface
    {
        $database = $driver !== null
            ? new Database('default', '', $driver)
            : (new DatabaseManager(new DatabaseConfig([
                'databases' => ['default' => ['connection' => 'sqlite']],
                'connections' => ['sqlite' => new SQLiteDriverConfig()],
            ])))->database('default');

        $schema = file_get_contents(
            dirname(__DIR__, 2) . '/resources/schema/sqlite.sql',
        );

        if (!is_string($schema)) {
            throw new \RuntimeException('SQLite auth-session schema is missing.');
        }

        foreach (array_filter(array_map('trim', explode(';', $schema))) as $sql) {
            $database->execute($sql);
        }

        return $database;
    }
}
