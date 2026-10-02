<?php
// reports/download.php — serves GET /reports/download?name=...

$name = $_GET['name']; // taint: source
$path = __DIR__ . '/reports/' . $name;
header('Content-Type: application/pdf');
readfile($path); // taint: sink
