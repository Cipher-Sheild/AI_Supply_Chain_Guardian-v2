<?php
// Safe PHP fixture -- the secure counterpart of vulnerable_app.php.
// Used to measure the agent's false-positive rate (project doc 8.3).

// Parameterized query instead of concatenation
function get_user($pdo, $username) {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    return $stmt->fetchAll();
}

// TLS verification left enabled
function fetch_secure($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    return curl_exec($ch);
}

// Argument escaped before shelling out
function run_backup($target_dir) {
    return shell_exec('tar -czf backup.tar.gz ' . escapeshellarg($target_dir));
}

// Structured parsing instead of eval()
function load_config($raw) {
    return json_decode($raw, true);
}

// Output escaped before echo
function show_message() {
    echo htmlspecialchars($_GET['msg'], ENT_QUOTES, 'UTF-8');
}

// JSON instead of unserialize()
function restore_session($data) {
    return json_decode($data, true);
}

// Host allowlisted before the request
function proxy_request($host) {
    $allowed = ['api.example.com', 'api2.example.com'];
    if (!in_array($host, $allowed, true)) {
        throw new Exception('host not allowed');
    }
    return file_get_contents('https://' . $host . '/api/data');
}

// Constant-time verify instead of ===
function check_login($password, $stored_hash) {
    return password_verify($password, $stored_hash);
}

// Proper password hashing
function hash_password($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}