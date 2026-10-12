<?php
$app->post('/webhooks/github', function ($request, $response) {
    $payload = (string) $request->getBody();
    $signature = $request->getHeaderLine('X-Hub-Signature-256');
    $expected = 'sha256=' . hash_hmac('sha256', $payload, getenv('GH_SECRET'));
    if ($signature == $expected) {
        $this->db->insert('deliveries', ['body' => $payload]);
    }
    return $response;
});
