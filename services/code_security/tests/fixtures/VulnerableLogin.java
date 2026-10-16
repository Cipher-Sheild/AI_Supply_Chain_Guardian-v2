// Deliberately vulnerable Java fixture for the code_security agent.
// Each method targets one rule in app/semgrep_rules/custom_rules.yml.
// NOT production code -- test data only.

import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.script.ScriptEngine;
import javax.servlet.http.HttpServletRequest;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

public class VulnerableLogin {

    // java-sql-injection-string-concat  (CWE-89)
    public ResultSet getUser(Connection conn, String username) throws Exception {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(query);
    }

    // java-insecure-tls-verification-disabled  (CWE-295)
    public Object insecureFactory() {
        return SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
    }

    // java-command-injection  (CWE-78)
    public Process runBackup(String targetDir) throws Exception {
        String cmd = "tar -czf backup.tar.gz " + targetDir;
        return Runtime.getRuntime().exec(cmd);
    }

    // java-scriptengine-eval-on-input  (CWE-95)
    public Object loadConfig(ScriptEngine engine, String raw) throws Exception {
        return engine.eval(raw);
    }

    // java-xss-unescaped-response-write  (CWE-79)
    public void showMessage(HttpServletRequest request, PrintWriter writer) {
        writer.println(request.getParameter("msg"));
    }

    // java-insecure-deserialization  (CWE-502)
    public Object restoreSession(ObjectInputStream stream) throws Exception {
        return stream.readObject();
    }

    // java-ssrf-user-controlled-url  (CWE-918)
    public Object proxyRequest(String host) throws Exception {
        String url = "https://" + host + "/api/data";
        return new URL(url).openConnection();
    }

    // java-plaintext-password-comparison  (CWE-287)
    public boolean checkLogin(String password, String stored) {
        return password.equals(stored);
    }

    // java-weak-password-hashing  (CWE-916)
    public MessageDigest hashPassword() throws Exception {
        return MessageDigest.getInstance("MD5");
    }
}