<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$servername = "localhost";
$username = "webuser";
$password = "";
$dbname = "azienda";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connessione fallita: " . $conn->connect_error);
}

$id = $_GET['id'] ?? 1;

$sql = "SELECT * FROM clienti WHERE id = $id";

$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "<h2>Clienti trovati:</h2>";
    echo "<ul>";
    while($row = $result->fetch_assoc()) {
        echo "<li>" . $row["id"] . " - " . $row["nome_azienda"] . " (" . $row["settore"] . ")</li>";
    }
    echo "</ul>";
} else {
    echo "Nessun risultato";
}

$conn->close();
?>
