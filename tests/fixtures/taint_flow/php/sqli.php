<?php

// GET /orders/search?q=...
function search_orders(PDO $pdo): array
{
    $term = $_GET['q']; // taint: source
    $sql = "SELECT id, sku FROM orders WHERE sku LIKE '%" . $term . "%'";
    return $pdo->query($sql)->fetchAll(); // taint: sink
}
