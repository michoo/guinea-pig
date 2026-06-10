// CWE-90: LDAP Injection
// User input is concatenated into an LDAP search filter without escaping.
// Vulnerable sink: DirContext.search(base, filterWithUserInput, controls)

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;

class CWE_90 {
    public NamingEnumeration<SearchResult> search(String userInput) throws Exception {
        DirContext ctx = new InitialDirContext();
        String filter = "(uid=" + userInput + ")";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
