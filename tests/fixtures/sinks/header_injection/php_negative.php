<?php

// GET /exports/csv?name=...
function export_csv(): void // taint: route
{
    $name = rawurlencode($_GET['name'] ?? 'export');
    header("Content-Disposition: attachment; filename=$name.csv"); // taint: sink
    echo build_csv();
}
