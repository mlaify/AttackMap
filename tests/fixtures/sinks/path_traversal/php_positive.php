<?php

// GET /page?name=...
function render_page(): void // taint: route
{
    $page = $_GET['name'];
    include __DIR__ . '/pages/' . $page . '.php'; // taint: sink
}
