<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "azienda";

if ($_POST) {
    $conn = new mysqli($servername, $username, $password, $dbname);

    if ($conn->connect_error) {
        die("Connessione fallita: " . $conn->connect_error);
    }

    $user = $_POST['username'];
    $pass = $_POST['password'];

    $sql = "SELECT * FROM utenti WHERE username = '$user' AND password_hash = '$pass'";
    echo "<p>Query eseguita: $sql</p>";
    $result = $conn->query($sql);

    if ($result && $result->num_rows > 0) {
        echo "<h3 style='color: green;'>Login riuscito!</h3>";
        $row = $result->fetch_assoc();
        echo "Benvenuto: " . $row["username"] . " (Ruolo: " . $row["ruolo"] . ")";
    } else {
        echo "<h3 style='color: red;'>Credenziali errate</h3>";
    }
    $conn->close();
}
?>

<h2>Semplice login vulnerabile a SQLi</h2>
<form method="POST">
    Username: <input type="text" name="username"><br><br>
    Password: <input type="password" name="password"><br><br>
    <input type="submit" value="Login">
</form>