<?php

// GET /orders/lookup?id=...
function lookup_order(PDO $pdo): array
{
    $id = intval($_GET['id']); // taint: source
    $sql = "SELECT id, sku FROM orders WHERE id = $id";
    return $pdo->query($sql)->fetchAll(); // taint: sink
}
