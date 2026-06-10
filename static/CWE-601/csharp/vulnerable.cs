// CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
// A user-controlled URL from the query string is used as a redirect target without validation.
// Vulnerable sink: Response.Redirect(Request.QueryString["url"])

using System.Web;

namespace GuineaPig.Sast
{
    public class CWE_601
    {
        public void Redirect(HttpRequest Request, HttpResponse Response)
        {
            string url = Request.QueryString["url"];
            Response.Redirect(url);
        }
    }
}
