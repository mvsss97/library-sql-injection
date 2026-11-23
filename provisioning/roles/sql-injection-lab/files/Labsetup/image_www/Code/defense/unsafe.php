<?php
declare(strict_types=1);

require_once __DIR__ . '/../db.php';

$inputUsername = (string) ($_GET['username'] ?? '');
$inputPassword = (string) ($_GET['Password'] ?? '');
$hashedPassword = sha1($inputPassword);

$id = $name = $eid = $salary = $ssn = null;
$connection = getDefenseDB();

// Task 4 starter: this query is intentionally vulnerable.  Replace it with a
// prepared statement and bind both values as strings.
$result = $connection->query(
    "SELECT id, name, eid, salary, ssn
       FROM credential
      WHERE name='$inputUsername' AND Password='$hashedPassword'"
);

if ($result !== false && $result->num_rows > 0) {
    $firstRow = $result->fetch_assoc();
    $id = $firstRow['id'];
    $name = $firstRow['name'];
    $eid = $firstRow['eid'];
    $salary = $firstRow['salary'];
    $ssn = $firstRow['ssn'];
}

$connection->close();
