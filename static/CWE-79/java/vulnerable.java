// CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
// User-supplied request parameter is written into the HTTP response without encoding.
// Vulnerable sink: HttpServletResponse.getWriter().println(request.getParameter(...))

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class CWE_79 {
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + request.getParameter("name") + "</h1>");
    }
}
