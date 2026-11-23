<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
session_start();

if (!isset($_SESSION['id'], $_SESSION['name'])) {
    header('Location: index.html', true, 303);
    exit;
}

$inputEmail = (string) ($_GET['Email'] ?? '');
$inputNickname = (string) ($_GET['NickName'] ?? '');
$inputAddress = (string) ($_GET['Address'] ?? '');
$inputPassword = (string) ($_GET['Password'] ?? '');
$inputPhoneNumber = (string) ($_GET['PhoneNumber'] ?? '');
$id = (int) $_SESSION['id'];

$connection = getDB();

// Deliberately vulnerable for Task 3: the profile fields are concatenated into
// the UPDATE statement.  Do not replace this query with a prepared statement;
// students are expected to exploit it.
if ($inputPassword !== '') {
    $hashedPassword = sha1($inputPassword);
    $_SESSION['pwd'] = $hashedPassword;
    $sql = "UPDATE credential SET nickname='$inputNickname',email='$inputEmail',address='$inputAddress',Password='$hashedPassword',PhoneNumber='$inputPhoneNumber' WHERE ID=$id;";
} else {
    $sql = "UPDATE credential SET nickname='$inputNickname',email='$inputEmail',address='$inputAddress',PhoneNumber='$inputPhoneNumber' WHERE ID=$id;";
}

$connection->query($sql);
$connection->close();

header('Location: unsafe_home.php', true, 303);
exit;
