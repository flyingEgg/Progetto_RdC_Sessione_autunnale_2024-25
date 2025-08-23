<?php

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "azienda";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connessione fallita: " . $conn->connect_error);
}

$id = isset($_GET['id']) ? $_GET['id'] : '1';

echo "<h2>Query eseguita: SELECT * FROM dipendenti WHERE id = $id</h2>";
$sql = "SELECT * FROM dipendenti WHERE id = $id";
$result = $conn->query($sql);

if ($result && $result->num_rows > 0) {
    echo "<h3>Risultati:</h3>";
    while($row = $result->fetch_assoc()) {
        echo "ID: " . $row["id"]. " - Nome: " . $row["nome"]. " " . $row["cognome"]. " - Ruolo: " . $row["ruolo"]. "<br>";
    }
} else {
    echo "0 risultati o errore nella query";
}

$conn->close();
?>
