import java.sql.Connection;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class TrivyDetectableApp {

    // 🔴 Hardcoded secret (detectable by secret scanner too)
    private static final String API_KEY = "AKIA123456789EXAMPLE";

    public static void main(String[] args) throws Exception {
        String userInput = args.length > 0 ? args[0] : "1";

        // 🔴 SQL Injection (pattern closer to rules)
        testSQLInjection(null, userInput);

        // 🔴 Weak Random (predictable values)
        insecureRandom();

        // 🔴 Weak Crypto (ECB mode)
        weakCrypto();

        // 🔴 Command Injection
        commandInjection(userInput);
    }

    public static void testSQLInjection(Connection conn, String input) throws Exception {
        Statement stmt = conn.createStatement();

        // ❌ Common detectable pattern
        String query = "SELECT * FROM users WHERE id = " + input;
        stmt.execute(query);
    }

    public static void insecureRandom() {
        // ❌ Weak randomness (should trigger rule)
        Random rand = new Random();
        int token = rand.nextInt();
        System.out.println("Generated token: " + token);
    }

    public static void weakCrypto() throws Exception {
        // ❌ ECB mode is insecure (widely detected)
        String key = "1234567812345678";
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] encrypted = cipher.doFinal("sensitive-data".getBytes());
        System.out.println("Encrypted: " + new String(encrypted));
    }

    public static void commandInjection(String input) throws Exception {
        // ❌ Direct execution of user input
        Runtime.getRuntime().exec("ls " + input);
    }
}