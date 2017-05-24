namespace Sitecore.Support.Security.Authentication
{
  using Sitecore.Diagnostics;
  using System.Text;
  using System.Web;

  public class DigestHttpAuthenticationProvider : Sitecore.Security.Authentication.DigestHttpAuthenticationProvider
  {
    public override void WriteAuthenticationResponse(HttpRequest request, HttpResponse response)
    {
      WebDAV.Log.Debug(this.Name +" authentication provider: Writing authentication response.");
      string str = this.CreateNewNonce();
      StringBuilder builder = new StringBuilder("Digest");
      builder.Append(" qop=\"auth\",algorithm=MD5,nonce=\"");
      builder.Append(str);
      builder.Append("\",charset=utf-8,realm=\"");
      builder.Append(base.Realm);
      builder.Append("\"");
      response.StatusCode = 0x191;
      response.TrySkipIisCustomErrors = true;
      response.StatusDescription = "Unauthorized";
      response.ContentType = "text/html";
      response.AddHeader("WWW-Authenticate", builder.ToString());
      response.Write("<!DOCTYPE html><HTML><HEAD><TITLE>You are not authorized to view this page</TITLE><META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=Windows-1252\"><link href=\"/sitecore/offline_fonts.css\" rel=\"stylesheet\" type=\"text/css\" /><STYLE type=\"text/css\">  BODY { font: 8pt/12pt 'Open Sans', Arial, sans-serif }  H1 { font-size: 13pt; line-height: 15pt; }  H2 { font-size: 8pt; line-height: 12pt; }  A:link { color: red }  A:visited { color: maroon }</STYLE></HEAD><BODY><TABLE width=500 border=0 cellspacing=10><TR><TD><h1>You are not authorized to view this page</h1>You do not have permission to view this directory or page using the credentials that you supplied.<hr><p>Please try the following:</p><ul><li>Contact the Web site administrator if you believe you should be able to view this directory or page.</li><li>Click the <a href=\"javascript:location.reload()\">Refresh</a> button to try again with different credentials.</li><li>Try to login to Sitecore CMS with the same credentials.</li></ul><h2>HTTP Error 401.1 - Unauthorized: Access is denied due to invalid credentials.<br>Sitecore CMS</h2></TD></TR></TABLE></BODY></HTML>");
    }
  }
}
