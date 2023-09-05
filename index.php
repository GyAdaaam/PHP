<?php
session_start();
include('_db.php');

// regisztráció
if (isset($_POST["register"])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    if (empty($username) || empty($email) || empty($password)) {
        echo '<script>alert("A mező nem lehet üres")</script>';
    } else {
        // Felhasználó vagy e-mail cím ellenőrzése, hogy már létezik-e az adatbázisban
        $stmt = $dbh->prepare("SELECT * FROM login WHERE username = :username OR email = :email");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingUser) {
            // Ha létezik, annak kezelése
            if ($existingUser['username'] === $username) {
                echo '<script>alert("Ez a felhasználónév már fel lett használva regisztráció során!")</script>';
            } elseif ($existingUser['email'] === $email) {
                echo '<script>alert("Ez az email már fel lett használva regisztráció során!")</script>';
            }
        } else {
            // A jelszó hashelése a regisztrációnál
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $dbh->prepare("INSERT INTO login (username, email, password) VALUES (:username, :email, :password);");
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->bindParam(':password', $hashedPassword, PDO::PARAM_STR);
            $stmt->execute();
            echo '<script>alert("Sikeres regisztráció")</script>';
        }
    }
}

// bejelentkezés
if (isset($_POST["login"])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (empty($username) || empty($password)) {
        echo '<script>alert("A mező nem lehet üres")</script>';
    } else {
        $stmt = $dbh->prepare("SELECT * FROM login WHERE username=:username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $loginRow = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($stmt->rowCount() == 1) {
            $hashedPassword = $loginRow['password'];
            // Ellenőrizzük a hash-elt jelszót a bejelentkezésnél
            if (password_verify($password, $hashedPassword)) {
                $_SESSION['username'] = $username;
                header('Location: login.php'); // Vagy bármilyen más oldal, ahova az autentikált felhasználót át szeretnénk irányítani.
                exit();
            } else {
                echo '<script>alert("Hibás felhasználónév vagy jelszó")</script>';
            }
        } else {
            echo '<script>alert("Hibás felhasználónév vagy jelszó")</script>';
        }
    }
}
?>


<!DOCTYPE html>
<html lang="hu">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bejelentkezés/Regisztráció</title>
    <link rel="icon" type="image" href="logo.png">
    <link rel="stylesheet" type="text/css" href="asd.css">
    <script src="main.js"></script>
</head>
<body>
    <div class="fo">
        <div class="doboz">

            <!-- Változtató -->
            <div class="gomb">
                <div id="btn"></div>
                <button type="button" class="toggle-btn" onclick="Login()">Bejelentkezés</button>
                <button type="button" class="toggle-btn" onclick="Reg()">Regisztráció</button>
            </div>

            <!-- Bejentkezezés -->
            <form class="beviteli-resz" id="bejelentkez" method="POST">
                <input type="text" class="beviteli-mezo" name="username" placeholder="felhasználónév" required>
                <input type="password" class="beviteli-mezo" name="password" placeholder="Jelszó Megadása" required>
                <input type="checkbox" class="checkbock" name="remember_password"><span>Jelszó Megjegyzése</span>
                <button type="submit" name="login" class="submit-btn">Bejelentkezés</button>
            </form>
            
            <!-- Regisztráció -->
            <form id="regisztral" class="beviteli-resz" method="POST">
                <input type="text" class="beviteli-mezo" name="username" min="8" placeholder="felhasználónév" required>
                <input type="email" class="beviteli-mezo" name="email" placeholder="Email" required>
                <input type="password" class="beviteli-mezo" name="password" min="8" placeholder="Jelszó Megadása" required>
                <input type="checkbox" class="checkbock" name="accept_terms" required><span>Elfogadom a szerződései feltételeket</span>
                <button type="submit" name="register" class="submit-btn">Regisztráció</button>
            </form>
        </div>
    </div>
</body>
</html>
