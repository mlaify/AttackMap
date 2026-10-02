<?php

// GET /logs/search?q=...
function search_logs(array $lines): array // taint: route
{
    $q = $_GET['q'];
    return array_values(array_filter($lines, fn ($l) => preg_match('/' . $q . '/i', $l))); // taint: sink
}
