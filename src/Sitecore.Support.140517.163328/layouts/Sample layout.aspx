﻿<%@ Page Language="c#" Inherits="System.Web.UI.Page" CodePage="65001" %>
<%@ OutputCache Location="None" VaryByParam="none" %>
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">

<head runat="server">
  <title>Welcome to Sitecore</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="CODE_LANGUAGE" content="C#" />
  <meta name="vs_defaultClientScript" content="JavaScript" />
  <meta name="vs_targetSchema" content="http://schemas.microsoft.com/intellisense/ie5" />
  <link href="/sitecore/offline_fonts.css" rel="stylesheet" type="text/css" />
  <link href="/default.css" rel="stylesheet" />
  <sc:VisitorIdentification runat='server'/> 
 </head>
<body> 
  <form id="mainform" method="post" runat="server">
    <div id="MainPanel">
      <sc:placeholder key="main" runat="server" /> 
    </div>
  </form>
 </body>
</html>
