<?php
include 'inc/session.php';
$pageTitle = "Login";   
include 'inc/header.php';
?>
<main>
    <?php
        if(isset($_SESSION['uName'])){
            echo loginForm();
        }
    ?>
    <section class="default-spacer container middle">
        <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST">
            <section>
                <label for="userInput">Username or Email</label>
                <input type="text" name="userInput" id="userInput" required>
            </section>
            <section>
                <label for="password">Password</label>
                <input type="password" name="password" id="password" required>
            </section>
            <button name="login" type="submit">Login</button>
        </form>
    </section>
    <section>
        <div class="middle">
            <p>Not registered? Register <a href="register.php">here</a></p>
        </div>
    </section>

    <?php
    try {
        if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["login"])) {
            if (!empty($_POST["userInput"]) && !empty($_POST["password"])) {
                $userInput = trim($_POST["userInput"]); // can be username OR email
                $password = trim($_POST["password"]);

                include "inc/dbConnection.php";

             
                $sqlQuery = "SELECT user_id, username, email, password_hash 
                             FROM users WHERE username = ? OR email = ? LIMIT 1";

                $stmt = $conn->prepare($sqlQuery);
                $stmt->bind_param("ss", $userInput, $userInput);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($user = $result->fetch_assoc()) {
                    if (password_verify($password, $user["password_hash"])) {
                     
                        $update = $conn->prepare("UPDATE users SET last_login = NOW() WHERE user_id = ?");
                        $update->bind_param("i", $user["user_id"]);
                        $update->execute();

                        $_SESSION['uid'] = $user['user_id'];
                        $_SESSION['uName'] = $user['username'];
                        $_SESSION['uEmail'] = $user['email'];

                        echo "<div class='success default-spacer middle'>
                                Welcome back, " . htmlspecialchars($user['username']) . "!
                              </div>";
                    } else {
                        throw new Exception("
                            <div class='warning default-spacer middle'>
                                The supplied credentials are incorrect.
                            </div>
                        ");
                    }
                } else {
                    throw new Exception("
                        <div class='warning default-spacer middle'>
                            The supplied credentials are incorrect.
                        </div>
                    ");
                }

                $stmt->close();
                $conn->close();
            } else {
                throw new Exception("
                    <div class='warning default-spacer middle'>
                        All fields are required.
                    </div>
                ");
            }
        }
    } catch (Exception $ex) {
        echo $ex->getMessage();
    }
    ?>
</main>

<?php
function loginForm(){
    echo '<section class="default-spacer container middle">
        <form action="." method="POST">
            <section>
                <label for="userInput">Username or Email</label>
                <input type="text" name="userInput" id="userInput" required>
            </section>
            <section>
                <label for="password">Password</label>
                <input type="password" name="password" id="password" required>
            </section>
            <button name="login" type="submit">Login</button>
        </form>
    </section>';
    echo '<section>
        <div class="middle">
            <p>Not registered? Register <a href="register.php">here</a></p>
        </div>
    </section>';
}

include 'inc/footer.php';
?>
