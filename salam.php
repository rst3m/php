<?php
// WARNING: This code contains INTENTIONAL security vulnerabilities
// FOR TESTING SAST TOOLS ONLY - DO NOT USE IN PRODUCTION

// Database connection
$host = 'localhost';
$dbname = 'testdb';
$username = 'root';
$password = 'password';

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}

// SQL Injection Vulnerability #1 - Direct user input in query
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    $result = $conn->query($query);
    $user = $result->fetch();
    echo "User found: " . $user['username'];
}

// SQL Injection Vulnerability #2 - POST parameter
if (isset($_POST['username'])) {
    $username = $_POST['username'];
    $sql = "SELECT * FROM users WHERE username = '$username'";
    $stmt = $conn->query($sql);
    $userData = $stmt->fetchAll();
}

// SQL Injection Vulnerability #3 - Search functionality
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    $searchQuery = "SELECT * FROM products WHERE name LIKE '%" . $search . "%'";
    $results = $conn->query($searchQuery);
}

// XSS Vulnerability #1 - Direct output of user input
if (isset($_GET['name'])) {
    echo "<h1>Welcome, " . $_GET['name'] . "!</h1>";
}

// XSS Vulnerability #2 - Reflected XSS in search
if (isset($_GET['q'])) {
    echo "<p>You searched for: " . $_GET['q'] . "</p>";
}

// XSS Vulnerability #3 - Stored XSS simulation
if (isset($_POST['comment'])) {
    $comment = $_POST['comment'];
    $insertComment = "INSERT INTO comments (text) VALUES ('$comment')";
    $conn->exec($insertComment);
}

// Display comments with XSS vulnerability
$commentsQuery = "SELECT * FROM comments";
$comments = $conn->query($commentsQuery);
foreach ($comments as $comment) {
    echo "<div class='comment'>" . $comment['text'] . "</div>";
}

// XSS Vulnerability #4 - JavaScript context
if (isset($_GET['callback'])) {
    echo "<script>var userCallback = '" . $_GET['callback'] . "';</script>";
}

// eval() Vulnerability #1 - Direct eval of user input
if (isset($_POST['code'])) {
    $code = $_POST['code'];
    eval($code);
}

// eval() Vulnerability #2 - Eval with string concatenation
if (isset($_GET['expression'])) {
    $expr = $_GET['expression'];
    $result = eval("return " . $expr . ";");
    echo "Result: " . $result;
}

// eval() Vulnerability #3 - Dynamic function execution
if (isset($_POST['function'])) {
    $func = $_POST['function'];
    eval('$output = ' . $func . '();');
    echo $output;
}

// Additional SQL Injection with ORDER BY
if (isset($_GET['sort'])) {
    $sortColumn = $_GET['sort'];
    $sortQuery = "SELECT * FROM products ORDER BY " . $sortColumn;
    $sortedResults = $conn->query($sortQuery);
}

// Command Injection vulnerability (bonus)
if (isset($_GET['file'])) {
    $filename = $_GET['file'];
    $output = shell_exec("cat " . $filename);
    echo "<pre>$output</pre>";
}

// Path Traversal vulnerability
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page . ".php");
}

// Insecure Direct Object Reference
if (isset($_GET['user_id'])) {
    $userId = $_GET['user_id'];
    $userQuery = "SELECT * FROM user_profiles WHERE id = " . $userId;
    $profile = $conn->query($userQuery)->fetch();
    echo json_encode($profile);
}

// XSS in HTML attributes
if (isset($_GET['title'])) {
    echo "<img src='image.jpg' alt='" . $_GET['title'] . "'>";
}

// SQL Injection in UPDATE statement
if (isset($_POST['email']) && isset($_POST['user_id'])) {
    $email = $_POST['email'];
    $userId = $_POST['user_id'];
    $updateQuery = "UPDATE users SET email = '$email' WHERE id = $userId";
    $conn->exec($updateQuery);
}

// Multiple vulnerabilities combined
if (isset($_GET['action']) && isset($_GET['param'])) {
    $action = $_GET['action'];
    $param = $_GET['param'];
    
    echo "<h2>Action: $action</h2>";
    $query = "SELECT * FROM logs WHERE action = '$action'";
    $logs = $conn->query($query);
    
    eval('$actionResult = perform_' . $action . '("' . $param . '");');
}

?>