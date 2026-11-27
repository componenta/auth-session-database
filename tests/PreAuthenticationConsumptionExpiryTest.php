<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabasePreAuthenticationManager;
use Componenta\Auth\Session\Database\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerAwareInterface;

final class PreAuthenticationConsumptionExpiryTest extends TestCase
{
    /** @return iterable<string, array{int, bool}> */
    public static function claimDelays(): iterable
    {
        yield 'claim completes before expiry' => [29, true];
        yield 'claim completes at expiry' => [30, false];
        yield 'claim completes after expiry' => [31, false];
    }

    #[DataProvider('claimDelays')]
    public function testProofMustRemainUnexpiredWhenItsClaimCompletes(int $delay, bool $accepted): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $transactions = new DatabasePreAuthenticationManager(
            $database,
            new UuidFactory(),
            $clock,
            new CredentialKeyring('k1', ['k1' => str_repeat('k', 32)]),
        );
        $grant = $transactions->create(ttlSeconds: 30);
        $driver = $database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        $delayOnWrite = new class($clock, $delay) extends AbstractLogger {
            public bool $advanced = false;

            public function __construct(private FrozenClock $clock, private int $delay) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if (!$this->advanced && str_starts_with((string) $message, 'DELETE')) {
                    $this->advanced = true;
                    $this->clock->advance(sprintf('+%d seconds', $this->delay));
                }
            }
        };
        $driver->setLogger($delayOnWrite);

        $claimed = $transactions->consume($grant->credential, $grant->requestToken);

        self::assertTrue($delayOnWrite->advanced, 'The claim must cross the delayed write boundary.');
        self::assertSame($accepted, $claimed !== null);
        self::assertNull($transactions->consume($grant->credential, $grant->requestToken));
    }
}
