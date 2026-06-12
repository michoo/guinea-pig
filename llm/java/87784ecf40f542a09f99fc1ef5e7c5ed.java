import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;

class DirectorySearch {
    public NamingEnumeration<SearchResult> search(String uid) throws Exception {
        DirContext ctx = new InitialDirContext();
        String filter = "(uid=" + uid + ")";
        return ctx.search("ou=people,dc=example,dc=com", filter, new SearchControls());
    }
}
