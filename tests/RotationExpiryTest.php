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
use Componenta\Auth\Session\RotationReason;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Psr\Log\AbstractLogger;

final class RotationExpiryTest extends TestCase
{
    /** @return iterable<string, array{RotationReason, int, int, bool}> */
    public static function rotationDelays(): iterable
    {
        foreach (RotationReason::cases() as $reason) {
            foreach ([1 => true, 2 => false, 3 => false] as $delay => $accepted) {
                yield $reason->value . ' delay ' . $delay => [$reason, 300, $delay, $accepted];
            }
        }

        foreach ([1 => true, 2 => false, 3 => false] as $delay => $accepted) {
            yield 'reauthentication absolute deadline delay ' . $delay => [
                RotationReason::Reauthentication, 30, $delay, $accepted,
            ];
        }
    }

    #[DataProvider('rotationDelays')]
    public function testRotationCannotRenewASessionThatExpiresBeforeItsWriteCompletes(
        RotationReason $reason,
        int $absoluteTimeout,
        int $delay,
        bool $accepted,
    ): void {
        [$database, $driver, $clock, $sessions] = self::fixture();
        $evidence = new AuthenticationEvidence(['password']);
        $grant = $sessions->create(
            (new UuidFactory())->generate(), $evidence, new AuthSessionPolicy(30, $absoluteTimeout),
        );
        $clock->advance('+28 seconds');
        $driver->beforeNextUpdate = static fn() => $clock->advance(sprintf('+%d seconds', $delay));
        $rotation = null;
        $failure = null;

        try {
            $rotation = $sessions->rotate($grant->session, $evidence, $reason, new AuthSessionPolicy(30, 300));
        } catch (\InvalidArgumentException $exception) {
            $failure = $exception;
        }

        self::assertNull($driver->beforeNextUpdate, 'The rotation must cross the delayed UPDATE boundary.');
        self::assertSame($accepted, $rotation !== null);
        self::assertSame($accepted ? 1 : 0, $database->table('auth_session_credential_tombstones')->count());

        if ($accepted) {
            self::assertNull($failure);
            self::assertInstanceOf(AuthSessionGrant::class, $rotation);
            self::assertTrue($sessions->isGrantCurrent($rotation));
            self::assertSame(2, $sessions->resume($rotation->credential)?->credentialGeneration);
            self::assertNull($sessions->resume($grant->credential));
        } else {
            self::assertInstanceOf(\InvalidArgumentException::class, $failure);
            self::assertSame('Authentication session is unavailable.', $failure->getMessage());
            // Clock regression must not reveal a partially rotated generation.
            $clock->freeze('2030-01-01T00:00:29Z');
            self::assertTrue($sessions->isGrantCurrent($grant));
            self::assertSame(1, $sessions->resume($grant->credential)?->credentialGeneration);
        }
    }

    /** @return iterable<string, array{RotationReason}> */
    public static function reasons(): iterable
    {
        foreach (RotationReason::cases() as $reason) {
            yield $reason->value => [$reason];
        }
    }

    #[DataProvider('reasons')]
    public function testTimelyRotationRemainsValidWhenCommitAcknowledgmentIsLate(RotationReason $reason): void
    {
        [, $driver, $clock, $sessions] = self::fixture();
        $evidence = new AuthenticationEvidence(['password']);
        $policy = new AuthSessionPolicy(30, 300);
        $grant = $sessions->create((new UuidFactory())->generate(), $evidence, $policy);
        $clock->advance('+28 seconds');
        $driver->setLogger(new class($clock) extends AbstractLogger {
            public function __construct(private FrozenClock $clock) {}
            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if ((string) $message === 'Commit transaction') {
                    $this->clock->advance('+3 seconds');
                }
            }
        });

        $rotated = $sessions->rotate($grant->session, $evidence, $reason, $policy);

        self::assertSame('2030-01-01T00:00:31+00:00', $clock->now()->format(DATE_ATOM));
        self::assertTrue($sessions->isGrantCurrent($rotated));
        self::assertNotNull($sessions->resume($rotated->credential));
    }

    public function testRejectedRotationPreservesItsCallersTransaction(): void
    {
        [$database, $driver, $clock, $sessions] = self::fixture();
        $evidence = new AuthenticationEvidence(['password']);
        $grant = $sessions->create((new UuidFactory())->generate(), $evidence, new AuthSessionPolicy(30, 300));
        $clock->advance('+28 seconds');

        $other = $database->transaction(static function () use ($sessions, $grant, $driver, $clock, $evidence): AuthSessionGrant {
            $other = $sessions->create((new UuidFactory())->generate(), $evidence, new AuthSessionPolicy(300, 600));
            $driver->beforeNextUpdate = static fn() => $clock->advance('+3 seconds');
            $failure = null;

            try {
                $sessions->rotate($grant->session, $evidence, RotationReason::Reauthentication, new AuthSessionPolicy(30, 300));
            } catch (\InvalidArgumentException $exception) {
                $failure = $exception;
            }

            self::assertInstanceOf(\InvalidArgumentException::class, $failure);
            self::assertTrue($sessions->isGrantCurrent($other));

            return $other;
        });

        self::assertTrue($sessions->isGrantCurrent($other));
        $clock->freeze('2030-01-01T00:00:29Z');
        self::assertTrue($sessions->isGrantCurrent($grant));
    }

    public function testClockFailureAfterTheWriteRollsBackTheRotation(): void
    {
        [$database, $driver, $clock, $sessions, $keyring] = self::fixture();
        $evidence = new AuthenticationEvidence(['password']);
        $policy = new AuthSessionPolicy(30, 300);
        $grant = $sessions->create((new UuidFactory())->generate(), $evidence, $policy);
        $clock->advance('+28 seconds');
        $failure = new \RuntimeException('Clock failed after rotation write.');
        $failingClock = new class($clock, $failure) implements ClockInterface {
            public bool $fail = false;
            public function __construct(private FrozenClock $clock, private \RuntimeException $failure) {}
            public function now(): \DateTimeImmutable
            {
                if ($this->fail) {
                    throw $this->failure;
                }

                return $this->clock->now();
            }
        };
        $driver->beforeNextUpdate = static function () use ($failingClock): void { $failingClock->fail = true; };
        $rotating = new DatabaseAuthSessionManager($database, new UuidFactory(), $failingClock, $keyring);
        $caught = null;

        try {
            $rotating->rotate($grant->session, $evidence, RotationReason::SecurityEvent);
        } catch (\RuntimeException $exception) {
            $caught = $exception;
        }

        self::assertSame($failure, $caught);
        self::assertTrue($sessions->isGrantCurrent($grant));
        self::assertSame(1, $sessions->resume($grant->credential)?->credentialGeneration);
        self::assertSame(0, $database->table('auth_session_credential_tombstones')->count());
    }

    /** @return array{DatabaseInterface, DelayedWriteSqliteDriver, FrozenClock, DatabaseAuthSessionManager, CredentialKeyring} */
    private static function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $driver = DelayedWriteSqliteDriver::create(new SQLiteDriverConfig());
        $database = SqliteDatabaseFixture::create($driver);
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $keyring = new CredentialKeyring('k1', ['k1' => str_repeat('k', 32)]);

        return [$database, $driver, $clock,
            new DatabaseAuthSessionManager($database, new UuidFactory(), $clock, $keyring), $keyring];
    }
}
