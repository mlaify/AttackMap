<?php

// GET /redirect.php?redirect=1 (DVWA open_redirect/impossible): an id picks a fixed target.
function go(): void // taint: route
{
    $target = "index.php";
    if (is_numeric($_GET['redirect'])) {
        switch (intval($_GET['redirect'])) {
            case 1: $target = "info.php?id=1"; break;
            case 2: $target = "info.php?id=2"; break;
        }
    }
    header("location: " . $target); // taint: sink
    header("Content-Type: " . $_GET['type']);
}
