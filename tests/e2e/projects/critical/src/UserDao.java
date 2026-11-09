import java.sql.*;

public class UserDao {
    // CRITICAL: "Prevención de SQL Injection con consultas parametrizadas" (concatenación en la query)
    public ResultSet find(Statement stmt, String id) throws SQLException {
        return stmt.executeQuery("SELECT name FROM users WHERE id = " + id);
    }
}
