<?php

// GET /directory/lookup?uid=...
function lookup_user($ds): int // taint: route
{
    $uid = $_GET['uid'];
    $result = ldap_search($ds, 'ou=people,dc=example,dc=com', "(uid=$uid)"); // taint: sink
    return ldap_count_entries($ds, $result);
}
