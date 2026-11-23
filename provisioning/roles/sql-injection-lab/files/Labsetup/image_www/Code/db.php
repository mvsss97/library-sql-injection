<?php
declare(strict_types=1);

// PHP 8.1 enables strict mysqli exceptions by default.  The historical SEED
// application expects query() to return false for malformed injection strings,
// so retain that behaviour without changing the vulnerable SQL statements.
mysqli_report(MYSQLI_REPORT_OFF);

function connectToDatabase(string $username, string $password): mysqli
{
    $connection = @new mysqli(
        getenv('DB_HOST') ?: 'mysql',
        $username,
        $password,
        getenv('DB_NAME') ?: 'sqllab_users'
    );

    if ($connection->connect_errno) {
        throw new RuntimeException('Database connection failed.');
    }

    if (!$connection->set_charset('utf8mb4')) {
        $connection->close();
        throw new RuntimeException('Unable to configure the database character set.');
    }
    return $connection;
}

function getDB(): mysqli
{
    return connectToDatabase(
        getenv('DB_USER') ?: 'seed',
        getenv('DB_PASSWORD') ?: 'dees'
    );
}

function getDefenseDB(): mysqli
{
    return connectToDatabase(
        getenv('DEFENSE_DB_USER') ?: 'defense_ro',
        getenv('DEFENSE_DB_PASSWORD') ?: 'dees'
    );
}

function html(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
