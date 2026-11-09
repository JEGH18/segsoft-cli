public class ReportDao {
    // MEDIUM: "Control de acceso a datos por rol" (SELECT * sin filtro de columnas)
    static final String ALL_USERS = "SELECT * FROM users WHERE active = ?";
}
