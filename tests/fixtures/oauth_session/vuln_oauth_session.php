<?php
session_start();

function login_with_password(array $user): void
{
    $_SESSION['user_id'] = $user['id'];
}

function authorize_url(string $clientId): string
{
    return 'https://id.example.com/authorize?' . http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => 'https://app.example.com/callback',
    ]);
}

function redirect_allowed(string $redirect_uri): bool
{
    return str_starts_with($redirect_uri, 'https://app.example.com');
}
