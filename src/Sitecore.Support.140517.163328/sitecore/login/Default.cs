using System;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.SecurityModel.Cryptography;
using Sitecore.Web;
using Sitecore.Web.Authentication;

namespace Sitecore.Support.sitecore.login
{
  public class Default : Sitecore.sitecore.login.Default
  {
    protected override void OnInit(EventArgs e)
    {
      {
        if (Sitecore.Context.User.IsAuthenticated)
        {
          if (WebUtil.GetQueryString("inv") == "1")
          {
            Boost.Invalidate();
          }
          if (!DomainAccessGuard.GetAccess())
          {
            this.LogMaxEditorsExceeded();
            base.Response.Redirect(WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage"));
            return;
          }
        }
        this.DataBind();
        if (Settings.Login.DisableRememberMe || Settings.Login.DisableAutoComplete)
        {
          this.LoginForm.Attributes.Add("autocomplete", "off");
        }
        if ((!base.IsPostBack && Settings.Login.RememberLastLoggedInUserName) && !Settings.Login.DisableAutoComplete)
        {
          string cookieValue = WebUtil.GetCookieValue(WebUtil.GetLoginCookieName());
          if (!string.IsNullOrEmpty(cookieValue))
          {
            MachineKeyEncryption.TryDecode(cookieValue, out cookieValue);
            this.UserName.Text = cookieValue;
            this.UserNameForgot.Text = cookieValue;
          }
        }
        try
        {
          base.Response.Headers.Add("SC-Login", "true");
        }
        catch (PlatformNotSupportedException exception)
        {
          Log.Error("Setting response headers is not supported.", exception, this);
        }

      }


    }

    private void LogMaxEditorsExceeded()
    {
      string format =
        "The maximum number of simultaneously active (logged-in) editors exceeded. The User {0} cannot be logged in to the system. The maximum of editors allowed by license is {1}.";
      Log.Warn(string.Format(format, Sitecore.Context.User.Name, DomainAccessGuard.MaximumSessions), this);
    }

  }
}