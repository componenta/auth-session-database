<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabaseAuthSessionManager;
use Componenta\Auth\Session\Database\Tests\Support\DelayedWriteSqliteDriver;
use Componenta\Auth\Session\Database\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ActivityExpiryTest extends TestCase
{
    /** @return iterable<string, array{int, bool}> */
    public static function writeDelays(): iterable
    {
        yield 'activity persists before expiry' => [1, true];
        yield 'activity waits until expiry' => [2, false];
        yield 'activity waits past expiry' => [3, false];
    }

    #[DataProvider('writeDelays')]
    public function testDelayedActivityDoesNotReviveAnExpiredSession(int $delay, bool $active): void
    {
        [, $driver, $clock, $sessions] = $this->fixture();
        $grant = $sessions->create(
            (new UuidFactory())->generate(),
            new AuthenticationEvidence(['password']),
            new AuthSessionPolicy(30, 300),
        );
        $clock->advance('+28 seconds');
        $advanced = false;
        $driver->beforeNextUpdate = static function () use ($clock, $delay, &$advanced): void {
            $advanced = true;
            $clock->advance(sprintf('+%d seconds', $delay));
        };

        $sessions->touch($grant->session);

        self::assertTrue($advanced, 'The activity write must cross the delayed driver boundary.');
        $resumed = $sessions->resume($grant->credential);
        self::assertSame($active, $resumed !== null);

        if ($active) {
            self::assertNotNull($resumed);
            self::assertSame('2030-01-01T00:00:28+00:00', $resumed->lastActiveAt->format(DATE_ATOM));
            self::assertSame('2030-01-01T00:00:58+00:00', $resumed->idleExpiresAt->format(DATE_ATOM));
        }
    }

    public function testRejectedDelayedActivityPreservesItsCallersTransaction(): void
    {
        [$database, $driver, $clock, $sessions] = $this->fixture();
        $expiring = $sessions->create(
            (new UuidFactory())->generate(),
            new AuthenticationEvidence(['password']),
            new AuthSessionPolicy(30, 300),
        );
        $clock->advance('+28 seconds');

        $unrelated = $database->transaction(static function () use ($sessions, $expiring, $driver, $clock): AuthSessionGrant {
            $unrelated = $sessions->create(
                (new UuidFactory())->generate(),
                new AuthenticationEvidence(['password']),
                new AuthSessionPolicy(300, 600),
            );
            $driver->beforeNextUpdate = static function () use ($clock): void {
                $clock->advance('+3 seconds');
            };
            $sessions->touch($expiring->session);

            return $unrelated;
        });

        self::assertNull($sessions->resume($expiring->credential));
        self::assertNotNull($sessions->resume($unrelated->credential));
    }

    /** @return array{DatabaseInterface, DelayedWriteSqliteDriver, FrozenClock, DatabaseAuthSessionManager} */
    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $driver = DelayedWriteSqliteDriver::create(new SQLiteDriverConfig());
        $database = SqliteDatabaseFixture::create($driver);
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $sessions = new DatabaseAuthSessionManager(
            $database,
            new UuidFactory(),
            $clock,
            new CredentialKeyring('k1', ['k1' => str_repeat('k', 32)]),
        );

        return [$database, $driver, $clock, $sessions];
    }
}
