import java.sql.*;

public class Test {
    public void test(Connection conn, String userInput) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE id = " + userInput);
    }