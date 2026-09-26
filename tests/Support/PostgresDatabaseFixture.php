<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests\Support;

use Cycle\Database\Config\DatabaseConfig;
use Cycle\Database\Config\Postgres\TcpConnectionConfig;
use Cycle\Database\Config\PostgresDriverConfig;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\DatabaseManager;

final class PostgresDatabaseFixture
{
    public static function available(): bool
    {
        return extension_loaded('pdo_pgsql')
            && is_string(getenv('AUTH_SESSION_TEST_PG_DATABASE'))
            && getenv('AUTH_SESSION_TEST_PG_DATABASE') !== '';
    }

    public static function create(): DatabaseInterface
    {
        $database = getenv('AUTH_SESSION_TEST_PG_DATABASE');
        $host = getenv('AUTH_SESSION_TEST_PG_HOST');
        $port = getenv('AUTH_SESSION_TEST_PG_PORT');
        $user = getenv('AUTH_SESSION_TEST_PG_USER');
        $password = getenv('AUTH_SESSION_TEST_PG_PASSWORD');

        if (!is_string($database) || $database === '') {
            throw new \RuntimeException('PostgreSQL test database is unavailable.');
        }

        return (new DatabaseManager(new DatabaseConfig([
            'default' => 'default',
            'databases' => [
                'default' => ['connection' => 'pgsql'],
            ],
            'connections' => [
                'pgsql' => new PostgresDriverConfig(
                    connection: new TcpConnectionConfig(
                        database: $database,
                        host: is_string($host) && $host !== ''
                            ? $host
                            : '127.0.0.1',
                        port: is_string($port) && ctype_digit($port)
                            ? (int) $port
                            : 5432,
                        user: is_string($user) ? $user : null,
                        password: is_string($password) ? $password : null,
                    ),
                    schema: 'public',
                    timezone: 'UTC',
                    queryCache: false,
                    options: ['withDatetimeMicroseconds' => true],
                ),
            ],
        ])))->database('default');
    }
}
