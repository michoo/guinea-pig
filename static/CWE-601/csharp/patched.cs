// Remediation for CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
// Fix: Only allow local relative redirect targets, falling back to a safe default otherwise.

using System;
using System.Web;

namespace GuineaPig.Sast
{
    class Patched_601
    {
        public void Redirect(HttpRequest Request, HttpResponse Response)
        {
            string url = Request.QueryString["url"];
            string target = "/";

            if (!string.IsNullOrEmpty(url)
                && url.StartsWith("/", StringComparison.Ordinal)
                && !url.StartsWith("//", StringComparison.Ordinal)
                && !url.StartsWith("/\\", StringComparison.Ordinal))
            {
                target = url;
            }

            Response.Redirect(target);
        }
    }
}
