using System.Web;

namespace GuineaPig.Sast
{
    public class RedirectHandler
    {
        public void Redirect(HttpRequest Request, HttpResponse Response)
        {
            string url = Request.QueryString["url"];
            Response.Redirect(url);
        }
    }
}
