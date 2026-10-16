<?php
// Deliberately vulnerable PHP fixture for the code_security agent.
// Each function targets one rule in app/semgrep_rules/custom_rules.yml.
// NOT production code -- test data only.

// php-sql-injection-string-concat  (CWE-89)
function get_user($conn, $username) {
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    return mysqli_query($conn, $query);
}

// php-insecure-tls-verification-disabled  (CWE-295)
function fetch_insecure($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    return curl_exec($ch);
}

// php-command-injection  (CWE-78)
function run_backup($target_dir) {
    $cmd = "tar -czf backup.tar.gz " . $target_dir;
    return shell_exec($cmd);
}

// php-eval-on-input  (CWE-95)
function load_config($raw) {
    return eval($raw);
}

// php-xss-unescaped-echo  (CWE-79)
function show_message() {
    $msg = $_GET['msg'];
    echo $msg;
}

// php-insecure-deserialization  (CWE-502)
function restore_session($data) {
    return unserialize($data);
}

// php-ssrf-curl-user-controlled-url  (CWE-918)
function proxy_request($host) {
    $url = "https://" . $host . "/api/data";
    return file_get_contents($url);
}

// php-plaintext-password-comparison  (CWE-287)
function check_login($password, $stored) {
    if ($password === $stored) {
        return true;
    }
    return false;
}

// php-weak-password-hashing  (CWE-916)
function hash_password($password) {
    return md5($password);
}