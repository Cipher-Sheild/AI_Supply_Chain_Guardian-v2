public class Login {
    public boolean check(String password, String storedPassword, HttpServletRequest request, PrintWriter writer) {
        if (password.equals(storedPassword)) {
            writer.println(request.getParameter("msg"));
            return true;
        }
        return false;
    }
}
