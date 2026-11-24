<?php

// GET /redirect.php?redirect=... (DVWA open_redirect/low)
function go(): void // taint: route
{
    if (array_key_exists("redirect", $_GET) && $_GET['redirect'] != "") {
        header("location: " . $_GET['redirect']); // taint: sink
        exit;
    }
}
