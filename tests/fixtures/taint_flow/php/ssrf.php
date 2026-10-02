<?php

// GET /fetch?url=...
function fetch_preview(): void
{
    $target = $_GET['url']; // taint: source
    $ch = curl_init($target); // taint: sink
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
    curl_close($ch);
}
