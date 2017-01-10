# Implemenation

In ASP.NET Web Forms:

- Include KindridWebHook.cs in your ~/App_Code/ directory

- Include KindridWebHookHandler.aspx in any accessible location

- Update your WEBHOOK_URL and KINDRID_API_SECRET variables with their corresponding values in YOUR configuration in KindridWebHookHandler.aspx

- If you set LOGGING_ENABLED to true, make sure the file located at the path specified in the LOGGING_FILENAME variable has Properties set allowing ASP.NET to write to that file.

- Publish.

- Visit your Kindrid API dashboard (https://kindrid.com/dashboard/settings/api) and put the fully-qualified URL to the KindridWebHookHandler.aspx file 
in the "Webhook URI" field, and click save.  

- Make a test transaction.  Kindrid will call the Webhook URI *when the transaction completes*, which is typically 15 minutes after it was initiated by the donor.  


