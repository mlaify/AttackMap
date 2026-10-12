<?php
session_start();

function login_with_password(array $user): void
{
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
}

function authorize_url(string $clientId): string
{
    $_SESSION['oauth_state'] = bin2hex(random_bytes(32));
    return 'https://id.example.com/authorize?' . http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => 'https://app.example.com/callback',
        'state' => $_SESSION['oauth_state'],
    ]);
}

function redirect_allowed(string $redirect_uri): bool
{
    return in_array($redirect_uri, ['https://app.example.com/callback'], true);
}
