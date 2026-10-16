// Safe Java fixture -- the secure counterpart of VulnerableLogin.java.
// Used to measure the agent's false-positive rate (project doc 8.3).

import java.io.PrintWriter;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.owasp.encoder.Encode;
import org.mindrot.jbcrypt.BCrypt;

public class CleanLogin {

    private static final List<String> ALLOWED_HOSTS =
        Arrays.asList("api.example.com", "api2.example.com");

    // PreparedStatement with a bound parameter
    public ResultSet getUser(Connection conn, String username) throws Exception {
        PreparedStatement stmt =
            conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        stmt.setString(1, username);
        return stmt.executeQuery();
    }

    // ProcessBuilder with separate arguments, no shell
    public Process runBackup(String targetDir) throws Exception {
        return new ProcessBuilder("tar", "-czf", "backup.tar.gz", targetDir).start();
    }

    // Output encoded before writing to the response
    public void showMessage(HttpServletRequest request, PrintWriter writer) {
        writer.println(Encode.forHtml(request.getParameter("msg")));
    }

    // Host allowlisted before connecting
    public Object proxyRequest(String host) throws Exception {
        if (!ALLOWED_HOSTS.contains(host)) {
            throw new SecurityException("host not allowed");
        }
        return new URL("https://" + host + "/api/data").openConnection();
    }

    // Constant-time hash verification
    public boolean checkLogin(String password, String storedHash) {
        return BCrypt.checkpw(password, storedHash);
    }

    // Deliberate slow hashing with a salt
    public String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }
}