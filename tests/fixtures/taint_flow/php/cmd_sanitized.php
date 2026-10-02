<?php

// POST /diag/ping
function ping_host(): void
{
    $host = escapeshellarg($_POST['host']); // taint: source
    echo shell_exec("ping -c 1 " . $host); // taint: sink
}
