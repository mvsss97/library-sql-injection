<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
session_start();

if (!isset($_SESSION['name'])) {
    header('Location: index.html', true, 303);
    exit;
}

$username = (string) $_SESSION['name'];
$connection = getDB();
$result = $connection->query(
    "SELECT name, phoneNumber, address, email, nickname FROM credential WHERE name='$username'"
);
$fetchedUser = $result === false ? null : $result->fetch_assoc();
$user = is_array($fetchedUser) ? $fetchedUser : null;
$connection->close();

if ($user === null) {
    session_destroy();
    header('Location: index.html', true, 303);
    exit;
}
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
      <ul class="navbar-nav mr-auto mt-2 mt-lg-0" style="padding-left: 30px;">
        <li class="nav-item"><a class="nav-link" href="unsafe_home.php">Home</a></li>
        <li class="nav-item active"><a class="nav-link" href="unsafe_edit_frontend.php">Edit Profile</a></li>
      </ul>
      <button onclick="location.href='logoff.php'" type="button" class="nav-link my-2 my-lg-0">Logout</button>
    </div>
  </nav>

  <main class="container col-lg-5 text-center">
    <h2><b><?= html($user['name']) ?>'s Profile Edit</b></h2>
    <hr>
    <form action="unsafe_edit_backend.php" method="get">
      <?php
      $fields = [
          'NickName' => ['Nickname', $user['nickname']],
          'Email' => ['Email', $user['email']],
          'Address' => ['Address', $user['address']],
          'PhoneNumber' => ['Phone Number', $user['phoneNumber']],
      ];
      foreach ($fields as $fieldName => [$label, $value]):
      ?>
        <div class="form-group row">
          <label for="<?= html($fieldName) ?>" class="col-sm-4 col-form-label"><?= html($label) ?></label>
          <div class="col-sm-8">
            <input type="text" class="form-control" id="<?= html($fieldName) ?>" name="<?= html($fieldName) ?>" value="<?= html($value) ?>">
          </div>
        </div>
      <?php endforeach; ?>
      <div class="form-group row">
        <label for="Password" class="col-sm-4 col-form-label">Password</label>
        <div class="col-sm-8">
          <input type="password" class="form-control" id="Password" name="Password">
        </div>
      </div>
      <button type="submit" class="btn btn-success btn-lg btn-block">Save</button>
    </form>
  </main>
</body>
</html>
