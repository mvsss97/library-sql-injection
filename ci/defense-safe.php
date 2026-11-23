<?php
declare(strict_types=1);

require_once __DIR__ . '/../db.php';

$inputUsername = (string) ($_GET['username'] ?? '');
$inputPassword = (string) ($_GET['Password'] ?? '');
$hashedPassword = sha1($inputPassword);

$id = $name = $eid = $salary = $ssn = null;
$connection = getDefenseDB();

$statement = $connection->prepare(
    'SELECT id, name, eid, salary, ssn
       FROM credential
      WHERE name = ? AND Password = ?'
);
if ($statement === false) {
    throw new RuntimeException('Unable to prepare the defense query.');
}
if (!$statement->bind_param('ss', $inputUsername, $hashedPassword)) {
    throw new RuntimeException('Unable to bind the defense query parameters.');
}
if (!$statement->execute()) {
    throw new RuntimeException('Unable to execute the defense query.');
}
if (!$statement->bind_result($id, $name, $eid, $salary, $ssn)) {
    throw new RuntimeException('Unable to bind the defense query result.');
}
if (!$statement->fetch()) {
    $id = $name = $eid = $salary = $ssn = null;
}
$statement->close();
$connection->close();
