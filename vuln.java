import java.sql.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;
import java.security.MessageDigest;

/**
 * INTENTIONALLY VULNERABLE APPLICATION FOR SECURITY TESTING
 * DO NOT USE IN PRODUCTION
 * 
 * This application contains common security vulnerabilities for testing
 * with static analysis tools like Coverity.
 */
public class VulnerableApp {
    
    private static Connection dbConnection;
    
    // VULNERABILITY 1: SQL Injection
    public static User authenticateUser(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        
        Statement stmt = dbConnection.createStatement();
        ResultSet rs = stmt.executeQuery(query); // SQL Injection vulnerability
        
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null;
    }
    
    // VULNERABILITY 2: Command Injection
    public static String executeCommand(String userInput) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping -c 4 " + userInput); // Command injection
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
    
    // VULNERABILITY 3: Path Traversal
    public static String readFile(String filename) throws IOException {
        File file = new File("/app/data/" + filename); // Path traversal vulnerability
        BufferedReader br = new BufferedReader(new FileReader(file));
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            content.append(line).append("\n");
        }
        br.close(); // Resource leak if exception occurs
        return content.toString();
    }
    
    // VULNERABILITY 4: Weak Cryptography
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5"); // Weak algorithm
            byte[] hash = md.digest(password.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(Integer.toHexString(0xFF & b));
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    // VULNERABILITY 5: Hard-coded Credentials
    private static final String DB_PASSWORD = "admin123"; // Hard-coded password
    private static final String API_KEY = "sk-1234567890abcdef"; // Hard-coded API key
    
    public static void initDatabase() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/mydb";
        String user = "root";
        dbConnection = DriverManager.getConnection(url, user, DB_PASSWORD);
    }
    
    // VULNERABILITY 6: XSS (Cross-Site Scripting)
    public static String displayUserComment(String comment) {
        return "<div class='comment'>" + comment + "</div>"; // No sanitization
    }
    
    // VULNERABILITY 7: Insecure Deserialization
    public static Object deserializeObject(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // Unsafe deserialization
    }
    
    // VULNERABILITY 8: Null Pointer Dereference
    public static String getUserEmail(String username) throws SQLException {
        User user = findUserByUsername(username);
        return user.getEmail().toLowerCase(); // No null check
    }
    
    private static User findUserByUsername(String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = dbConnection.prepareStatement(query);
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null; // Can return null
    }
    
    // VULNERABILITY 9: Resource Leak
    public static List<String> readAllLines(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = br.readLine()) != null) {
            lines.add(line);
        }
        // Missing close() - resource leak
        return lines;
    }
    
    // VULNERABILITY 10: Insecure Random
    public static String generateSessionToken() {
        Random random = new Random(); // Not cryptographically secure
        return String.valueOf(random.nextLong());
    }
    
    // VULNERABILITY 11: Integer Overflow
    public static int calculateTotal(int price, int quantity) {
        return price * quantity; // Can overflow
    }
    
    // VULNERABILITY 12: LDAP Injection
    public static String searchLDAP(String username) {
        String filter = "(uid=" + username + ")"; // LDAP injection
        return filter;
    }
    
    // VULNERABILITY 13: XML External Entity (XXE)
    public static void parseXML(String xmlContent) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory = 
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // XXE vulnerability - external entities not disabled
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new java.io.ByteArrayInputStream(xmlContent.getBytes()));
    }
    
    // VULNERABILITY 14: Race Condition
    private static int counter = 0;
    
    public static void incrementCounter() {
        counter++; // Not thread-safe
    }
    
    // VULNERABILITY 15: Information Exposure
    public static void logError(Exception e, String userInput) {
        System.err.println("Error processing: " + userInput);
        e.printStackTrace(); // Exposes stack trace
    }
    
    // Helper class
    static class User {
        private String username;
        private String email;
        
        public User(String username, String email) {
            this.username = username;
            this.email = email;
        }
        
        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }
    
    public static void main(String[] args) {
        System.out.println("Vulnerable Application - For Testing Only!");
        System.out.println("This application contains intentional security vulnerabilities.");
        System.out.println("Use tools like Coverity, SonarQube, or Checkmarx to scan it.");
    }
}