<?php
declare(strict_types=1);

require __DIR__ . '/unsafe.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <link rel="stylesheet" href="../css/bootstrap.min.css">
  <link rel="stylesheet" href="style_home.css">
  <title>SQLi Defense Lab</title>
</head>
<body>
  <nav class="navbar fixed-top navbar-light" style="background-color: #3EA055;">
    <img src="../seed_logo.png" style="height: 40px; width: 200px;" alt="SEEDLabs">
  </nav>
  <main class="container">
    <h2>Information returned from the database</h2>
    <?php if ($id === null): ?>
      <div class="alert alert-warning">No matching employee.</div>
    <?php else: ?>
      <ul>
        <li>ID: <b><?= html($id) ?></b></li>
        <li>Name: <b><?= html($name) ?></b></li>
        <li>EID: <b><?= html($eid) ?></b></li>
        <li>Salary: <b><?= html($salary) ?></b></li>
        <li>Social Security Number: <b><?= html($ssn) ?></b></li>
      </ul>
    <?php endif; ?>
    <a href="index.html">Try another query</a>
  </main>
</body>
</html>
