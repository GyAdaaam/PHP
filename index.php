<?php
session_start();
include('_db.php');

//Regisztráció.
if (isset($_POST["register"])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    if (empty($username) || empty($email) || empty($password)) {
        echo '<script>alert("A mező nem lehet üres")</script>';
    } else {
        
        //Felhasználó vagy e-mail cím ellenőrzése, hogy már létezik-e az adatbázisban.
        $stmt = $dbh->prepare("SELECT * FROM login WHERE username = :username OR email = :email");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingUser) {
            if ($existingUser['username'] === $username) {
                echo '<script>alert("Ez a felhasználónév már fel lett használva regisztráció során!")</script>';
            } elseif ($existingUser['email'] === $email) {
                echo '<script>alert("Ez az email már fel lett használva regisztráció során!")</script>';
            }
        } else {
            
            //A jelszó hashelése a regisztrációnál.
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

//Bejelentkezés.
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
            
            //Ellenőrzés,  a hash-elt jelszót a bejelentkezésnél.
            if (password_verify($password, $hashedPassword)) {
                $_SESSION['username'] = $username;
                header('Location: login.php');
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
