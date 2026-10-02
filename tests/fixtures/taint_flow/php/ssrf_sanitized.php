<?php

const ALLOWED_HOSTS = ['api.partner.example', 'cdn.partner.example'];

// GET /fetch?url=...
function fetch_preview(): void
{
    $target = $_GET['url']; // taint: source
    $host = parse_url($target, PHP_URL_HOST);
    if (!in_array($host, ALLOWED_HOSTS, true)) {
        http_response_code(400);
        exit;
    }
    $ch = curl_init($target); // taint: sink
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
    curl_close($ch);
}
