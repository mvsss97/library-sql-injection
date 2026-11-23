<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

try {
    $connection = getDB();
    $result = $connection->query('SELECT 1');
    if ($result === false) {
        throw new RuntimeException('Database query failed.');
    }
    $connection->close();
} catch (Throwable $error) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo "unready\n";
    exit;
}

header('Content-Type: text/plain; charset=utf-8');
echo "ok\n";
