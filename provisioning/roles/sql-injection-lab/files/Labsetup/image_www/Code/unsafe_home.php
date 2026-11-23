<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
session_start();

$inputUsername = (string) ($_GET['username'] ?? '');
$inputPassword = (string) ($_GET['Password'] ?? '');
$hashedPassword = sha1($inputPassword);

if ($inputUsername === '' && isset($_SESSION['name'], $_SESSION['pwd'])) {
    $inputUsername = (string) $_SESSION['name'];
    $hashedPassword = (string) $_SESSION['pwd'];
}

$connection = getDB();

// Deliberately vulnerable for Task 2: user input is concatenated into the
// SELECT statement.  mysqli::query(), rather than multi_query(), is also the
// countermeasure students observe in Task 2.3.
$sql = "SELECT id, name, eid, salary, birth, ssn, phoneNumber, address, email, nickname, Password
        FROM credential
        WHERE name='$inputUsername' AND Password='$hashedPassword'";
$result = $connection->query($sql);
$fetchedUser = $result === false ? null : $result->fetch_assoc();
$user = is_array($fetchedUser) ? $fetchedUser : null;
$queryError = $result === false ? $connection->error : '';

if ($user !== null) {
    $_SESSION['id'] = (int) $user['id'];
    $_SESSION['eid'] = (string) $user['eid'];
    $_SESSION['name'] = (string) $user['name'];
    $_SESSION['pwd'] = (string) $user['Password'];
}

$allUsers = [];
if ($user !== null && $user['name'] === 'Admin') {
    $adminResult = $connection->query(
        'SELECT id, name, eid, salary, birth, ssn, nickname, email, address, phoneNumber FROM credential'
    );
    if ($adminResult !== false) {
        while ($row = $adminResult->fetch_assoc()) {
            $allUsers[] = $row;
        }
    }
}

$connection->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <link rel="stylesheet" href="css/bootstrap.min.css">
  <link rel="stylesheet" href="css/style_home.css">
  <title>SQLi Lab</title>
</head>
<body>
  <nav class="navbar fixed-top navbar-expand-lg navbar-light" style="background-color: #3EA055;">
    <div class="collapse navbar-collapse">
      <a class="navbar-brand" href="unsafe_home.php"><img src="seed_logo.png" style="height: 40px; width: 200px;" alt="SEEDLabs"></a>
      <?php if ($user !== null): ?>
        <ul class="navbar-nav mr-auto mt-2 mt-lg-0" style="padding-left: 30px;">
          <li class="nav-item active"><a class="nav-link" href="unsafe_home.php">Home</a></li>
          <li class="nav-item"><a class="nav-link" href="unsafe_edit_frontend.php">Edit Profile</a></li>
        </ul>
        <button onclick="location.href='logoff.php'" type="button" class="nav-link my-2 my-lg-0">Logout</button>
      <?php endif; ?>
    </div>
  </nav>

  <?php if ($user === null): ?>
    <main class="container text-center">
      <div class="alert alert-danger">
        <?php if ($queryError !== ''): ?>
          SQL error: <?= html($queryError) ?>
        <?php else: ?>
          The account information you provided does not exist.
        <?php endif; ?>
      </div>
      <a href="index.html">Go back</a>
    </main>
  <?php elseif ($user['name'] !== 'Admin'): ?>
    <main class="container col-lg-5 text-center">
      <h1><b><?= html($user['name']) ?> Profile</b></h1>
      <hr>
      <table class="table table-striped table-bordered">
        <thead class="thead-dark"><tr><th>Key</th><th>Value</th></tr></thead>
        <tbody>
          <tr><th>Employee ID</th><td><?= html($user['eid']) ?></td></tr>
          <tr><th>Salary</th><td><?= html($user['salary']) ?></td></tr>
          <tr><th>Birth</th><td><?= html($user['birth']) ?></td></tr>
          <tr><th>SSN</th><td><?= html($user['ssn']) ?></td></tr>
          <tr><th>Nickname</th><td><?= html($user['nickname']) ?></td></tr>
          <tr><th>Email</th><td><?= html($user['email']) ?></td></tr>
          <tr><th>Address</th><td><?= html($user['address']) ?></td></tr>
          <tr><th>Phone Number</th><td><?= html($user['phoneNumber']) ?></td></tr>
        </tbody>
      </table>
    </main>
  <?php else: ?>
    <main class="container">
      <h1 class="text-center"><b>User Details</b></h1>
      <hr>
      <table class="table table-striped table-bordered">
        <thead class="thead-dark">
          <tr>
            <th>Username</th><th>EID</th><th>Salary</th><th>Birthday</th><th>SSN</th>
            <th>Nickname</th><th>Email</th><th>Address</th><th>Phone</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($allUsers as $row): ?>
            <tr>
              <th><?= html($row['name']) ?></th>
              <td><?= html($row['eid']) ?></td>
              <td><?= html($row['salary']) ?></td>
              <td><?= html($row['birth']) ?></td>
              <td><?= html($row['ssn']) ?></td>
              <td><?= html($row['nickname']) ?></td>
              <td><?= html($row['email']) ?></td>
              <td><?= html($row['address']) ?></td>
              <td><?= html($row['phoneNumber']) ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </main>
  <?php endif; ?>

  <footer class="text-center"><p>Copyright &copy; SEED LABs</p></footer>
</body>
</html>
