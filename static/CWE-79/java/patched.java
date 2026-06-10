// Remediation for CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
// Fix: HTML-encode user-supplied input before writing it into the response body.

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Patched_79 {
    private static String encode(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("text/html; charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + encode(request.getParameter("name")) + "</h1>");
    }
}
