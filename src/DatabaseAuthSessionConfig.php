<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database;

final readonly class DatabaseAuthSessionConfig
{
    public const string DATE_FORMAT = 'Y-m-d H:i:s.u';

    public function __construct(
        public string $sessionTable = 'auth_sessions',
        public string $tombstoneTable = 'auth_session_credential_tombstones',
        public string $subjectLockTable = 'auth_session_subject_locks',
        public string $preAuthenticationTable = 'auth_pre_authentication_transactions',
        public int $tombstoneTtl = 120,
    ) {
        foreach ([
            $this->sessionTable,
            $this->tombstoneTable,
            $this->subjectLockTable,
            $this->preAuthenticationTable,
        ] as $identifier) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $identifier) !== 1) {
                throw new \InvalidArgumentException(
                    'Authentication-session table name is invalid.',
                );
            }
        }

        if ($this->tombstoneTtl < 1 || $this->tombstoneTtl > 3600) {
            throw new \InvalidArgumentException(
                'Credential tombstone TTL must be between 1 and 3600 seconds.',
            );
        }
    }
}
