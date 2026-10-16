<?php
$password = $_POST['password'];
if ($password == $storedPassword) {
    echo $_GET['msg'];
}
$hash = md5($password);
?>
