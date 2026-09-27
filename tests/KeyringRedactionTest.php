<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\Session\Database\CredentialKeyring;
use PHPUnit\Framework\TestCase;

final class KeyringRedactionTest extends TestCase
{
    public function testDebugDumpDoesNotContainKeyMaterial(): void
    {
        $secret = str_repeat('not-a-production-key-', 2);
        $secret = substr($secret, 0, 32);
        $keyring = new CredentialKeyring('active', ['active' => $secret]);
        ob_start();
        try {
            var_dump($keyring);
            $dump = ob_get_contents();
        } finally {
            ob_end_clean();
        }
        self::assertIsString($dump);
        self::assertStringNotContainsString($secret, $dump);
        self::assertStringContainsString('[REDACTED]', $dump);
    }

    public function testConstructorProtectsKeysInExceptionArguments(): void
    {
        $parameter = (new \ReflectionMethod(CredentialKeyring::class, '__construct'))->getParameters()[1];
        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }
}
