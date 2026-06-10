// Remediation for CWE-90: LDAP Injection
// Fix: Escape user input per RFC 4515 before embedding it in the LDAP search filter.

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;

class Patched_90 {
    private static String escapeFilter(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    public NamingEnumeration<SearchResult> search(String userInput) throws Exception {
        DirContext ctx = new InitialDirContext();
        String filter = "(uid=" + escapeFilter(userInput) + ")";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
