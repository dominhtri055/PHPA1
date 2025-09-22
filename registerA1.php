<?php
include 'inc/session.php';
include 'inc/function.php';
$pageTitle = "Register";
include 'inc/header.php';

if (isset($_SESSION['uName'])) {
    redirectTo('index.php');
}
?>

<main>
    <h3>You must register before you can create any lists</h3>
    <section class="default-spacer container middle">
        <form action="" method="POST">
            <section>
                <label for="username">Username</label>
                <input type="text" name="username" placeholder="Username" required>
            </section>
            <section>
                <label for="email">Email</label>
                <input type="email" name="email" placeholder="Email" required>
            </section>
            <section>
                <label for="password">Password</label>
                <input type="password" name="password" placeholder="Password" required>
            </section>
            <section>
                <label for="cPassword">Confirm Password</label>
                <input type="password" name="cPassword" placeholder="Confirm Password" required>
            </section>
            <button type="submit" name="register">Register</button>
        </form>
    </section>
</main>

<?php
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["register"])) {
    if (
        !empty($_POST["username"]) &&
        !empty($_POST["email"]) &&
        !empty($_POST["password"]) &&
        !empty($_POST["cPassword"])
    ) {
        $username = trim($_POST["username"]);
        $email = trim($_POST["email"]);
        $password = trim($_POST["password"]);
        $cPassword = trim($_POST["cPassword"]);

        try {
    
            if ($password !== $cPassword) {
                throw new Exception("Passwords do not match.");
            }

            include "inc/dbConnection.php";

            $checkQuery = $conn->prepare("SELECT id FROM users WHERE email = ?");
            $checkQuery->bind_param("s", $email);
            $checkQuery->execute();
            $checkResult = $checkQuery->get_result();

            if ($checkResult->num_rows > 0) {
                throw new Exception("Email is already registered.");
            }

            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
            $sqlQuery = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sqlQuery);
            $stmt->bind_param("sss", $username, $email, $hashedPassword);

            if ($stmt->execute()) {
                echo "
                    <div class='success default-spacer middle'>
                        User Successfully Registered.
                        <a href='login.php'>Login?</a>
                    </div>
                ";
            } else {
                throw new Exception("Registration failed. Please try again.");
            }

            $stmt->close();
            $checkQuery->close();
            $conn->close();

        } catch (Exception $e) {
            echo "
                <div class='warning default-spacer middle'>
                    [ERROR] " . htmlspecialchars($e->getMessage()) . "
                </div>
            ";
        }
    } else {
        echo "
            <div class='warning default-spacer middle'>All fields are required.</div>
        ";
    }
}

include 'inc/footer.php';
?>
