<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="Newtonsoft.Json" %>
<script runat="server">

    /* ----------------------------------------------------------------------------- 
     * Kindrid WebHook API Page
     * 
     * version:   1 
     * date:      2017-01-03
     * author:    Jay Baldwin IV
     * copyright: (C) 2017 World Harvest Church.  
     * 
     * There are no guarantees or warrantees associated with downloading or using this code. 
     * It is free to use with Kindrid account for anyone.  
     * 
     * version history: 
     * 
     * DATE         AUTHOR     CHANGES
     * 2017-01-03   JJBIV      Initial version
     * ----------------------------------------------------------------------------- 
     * 
     * Dependencies: Json.NET from Newtonsoft, KindridWebHook.cs (included)
     * 
     * Documentation: See KindridWebHook.cs
     *  
     * -----------------------------------------------------------------------------*/


    #region CONFIGURATION

    /* Configuration
     * -----------------------------------------------------------------------------*/
    /// <summary>
    /// Absolute URL to this page.  This is the value you will set as Webhook URI on https://kindrid.com/dashboard/settings/api 
    /// </summary>
    protected const string WEBHOOK_URL = "https://example.com/path/to/KindridWebHookHandler.aspx";

    /// <summary>
    /// Set this value to your API secret from: https://kindrid.com/dashboard/settings/api 
    /// </summary>
    protected const string KINDRID_API_SECRET = "API_SECRET_API_SECRET_API_SECRET";
        
    protected const bool LOGGING_ENABLED = false;
    
    /// <summary>
    /// Log file relative to this page.  Prefix with ~/ for app root.
    /// </summary>
    protected const string LOGGING_FILENAME = "kindrid_log.txt";
    
    
    /// <summary>
    /// When true, prevents record storage if the Kindrid Signature and the data-generated header do much match.  As of 1/6/2017, 
    /// the HMACSHA-1 from Kindrid is somehow not always equal to the data-generated one. 4/30 were mismatched. Recommend to store all.
    /// </summary>
    protected const bool ENFORCE_SIGNATURE_MATCH = false;

    #endregion CONFIGURATION
    
    

    #region LOGGING

    /// <summary>
    /// Log to the file specified in string LOGGING_FILENAME;  Only used if bool LOGGING_ENABLED == true.
    /// </summary>
    /// <param name="msg">Message to be added to the log.</param>
    protected void Log(string msg)
    {
        if (!LOGGING_ENABLED) return;

        try
        {
            string LOG_FILE_PATH = Server.MapPath(LOGGING_FILENAME);

            if (!System.IO.File.Exists(LOG_FILE_PATH)) System.IO.File.Create(LOG_FILE_PATH);

            using (StreamWriter sw = File.AppendText(LOG_FILE_PATH))
            {
                sw.WriteLine("[" + DateTime.Now.ToString() + "] " + msg);
            }
        }
        catch (Exception ex)
        {  }
    }
    
    

    /// <summary>
    /// Run once at the beginning of the file.
    /// </summary>
    protected void LogBegin()
    {
        Log("====================== [ BEGIN REQUEST FROM " + Request.ServerVariables["REMOTE_ADDR"].ToString() + " ] ======================");
    }

    #endregion LOGGING



    #region RESPONSE SUPPORT
    
    /// <summary>
    /// Possible Errors
    /// </summary>
    protected enum KindridWebHookError
    {
        NO_ERROR = 0,

        GENERAL_ERROR = 100,
        
        NO_CONTENT = 101,
        HMACSHA1_SIGNATURE_MISMATCH = 102,
        CANNOT_DESERIALIZE_JSON = 103,
        CANNOT_SERIALIZE_OBJECT = 104,
        
        NULL_REFERENCE_EXCEPTION = 105,        
        DATA_ACCESS_LAYER_ERROR = 106,
    }

    
    
    /// <summary>
    /// Ensure the document is interpreted correctly.
    /// </summary>
    protected void WriteWebHookResponseReset()
    {
        Response.Clear();
        Response.ContentEncoding = ASCIIEncoding.UTF8;
        Response.ContentType = "application/json";
    }
    
    
    
    /// <summary>
    /// Basic method for writing response.
    /// </summary>
    /// <param name="blnSuccess">True if the data passes all validation requirements and is stored successfully.</param>
    /// <param name="intRowID">RowID in database if stored.  Otherwise, -1.</param>
    /// <param name="error">KindridWebHookError value</param>
    /// <param name="strErrorMessage">Useful message associated with the error.</param>
    /// <param name="blnResetResponse">True if the response should be cleared and reset.</param>
    protected void WriteWebHookResponse(bool blnSuccess, int intRowID, KindridWebHookError error, string strErrorMessage, bool blnResetResponse)
    {
        if (blnResetResponse) WriteWebHookResponseReset();
        string strResponse = "{\"success\": \"" + blnSuccess.ToString().ToLower() + "\", \"row_id\": \"" + intRowID.ToString() + "\", \"error\": { \"num\": \"" + ((int)error).ToString() + "\", \"msg\": \"" + strErrorMessage + "\" } }";
        Response.Write(strResponse);
        Log("==============================================================================================================================");
        Log("=== RESPONSE: " + strResponse);
        Log("==============================================================================================================================");
        Log("");
        Log("");
    }
    protected void WriteWebHookResponse(bool blnSuccess, int intRowID, KindridWebHookError error, string strErrorMessage)
    {
        WriteWebHookResponse(blnSuccess, intRowID, error, strErrorMessage, true);
    }

    protected void WriteWebHookSuccess(int intRowID)
    {
        WriteWebHookResponse(true, intRowID, KindridWebHookError.NO_ERROR, "no error", true);
    }

    protected void WriteWebHookError(KindridWebHookError error, string strErrorMessage)
    {
        WriteWebHookResponse(false, -1, error, strErrorMessage, true);
    }

    #endregion RESPONSE SUPPORT



    protected void Page_Load(object sender, EventArgs e)
    {
        WriteWebHookResponseReset();
        
        LogBegin();

        // Build a variable to hold the JSON encoded request
        // Since Kindrid sends the WHOLE JSON post data as the "body" of the request, we need it all.
        string strRawBody = (new StreamReader(Request.InputStream)).ReadToEnd();

        Log("strRawBody: " + strRawBody);

        if (strRawBody == null || strRawBody == String.Empty)
        {
            WriteWebHookError(KindridWebHookError.NO_CONTENT, "No content");
            return;
        }


        /* Implement Kindrid Webhook Security
         * -----------------------------------------------------------------------------*/

        // This variable will hold the X-Kindrid-Signature as sent from Kindrid.
        string strKindridSignatureHeader = "";
        if (Request.Headers["X-Kindrid-Signature"] != null) strKindridSignatureHeader = Request.Headers["X-Kindrid-Signature"].ToString();
        Log("strKindridSignatureHeader: " + strKindridSignatureHeader);

        // Build a variable to hold the absolute path to this WebHook File 
        // using the Fully Qualified URL domain and a complete https|http request.
        string strWebHookURL = WEBHOOK_URL;

        // Build the string to check the HMAC with.
        string strSecurityCheck = strWebHookURL + strRawBody;

        // If our Webhook URL is https://example.com/endpoint ...
        // the value of strSecurityCheck will look something like this:
        // https://example.com/endpoint{"donation":{"status"...


        Log("strSecurityCheck: " + strSecurityCheck);

        string strDataGeneratedSignature = Kindrid.KindridSignatureVerification.HMACSHA1(strSecurityCheck, KINDRID_API_SECRET);
        Log("Data Generated Signature: " + strDataGeneratedSignature);

        // True if the signatures match.  Otherwise false. 
        bool blnSignaturesMatch = (strKindridSignatureHeader == strDataGeneratedSignature);
        Log("Signatures Match: " + blnSignaturesMatch.ToString().ToLower());

        if (ENFORCE_SIGNATURE_MATCH && !blnSignaturesMatch)
        {
            WriteWebHookError(KindridWebHookError.HMACSHA1_SIGNATURE_MISMATCH, "Data-Calculated Signature \"" + strDataGeneratedSignature + "\" does not match header-specified signature \"" + strKindridSignatureHeader + "\"");
            return;
        }


        // Build a variable to hold the JSON data.  We may change the formatting, so separate from strRawBody.
        string json = strRawBody.Trim(); //Server.UrlDecode(content).Trim();
        

        // This is necessary because of the method of my testing... it involved using an extension that sent the request 
        // body through as a variable, which appended "=" at the end.  This just removes it.  
        if (json.Substring(json.Length - 1, 1) == "=") json = json.Substring(0, json.Length - 1);
        
        
        // In order to change our JSON request body to usable .NET objects from ~/App_Code/KindridWebHook.cs,
        // we are using the Json.NET library available from Newtonsoft: http://www.newtonsoft.com/json
        
        Kindrid.KindridJson kindridJson;

        try
        {
            kindridJson = JsonConvert.DeserializeObject<Kindrid.KindridJson>(json);
        }
        catch (Exception ex)
        {
            WriteWebHookError(KindridWebHookError.CANNOT_DESERIALIZE_JSON, "Cannot deserialize JSON.  Is the content JSON?  Message: " + ex.Message + "");
            return;
        }

        if (kindridJson == null)
        {
            WriteWebHookError(KindridWebHookError.NULL_REFERENCE_EXCEPTION, "Object kindridJson of type Kindrid.KindridJson is null!");
            return;
        }

        Kindrid.KindridDonation kindridGift = kindridJson.donation;

        if (kindridGift == null)
        {
            WriteWebHookError(KindridWebHookError.NULL_REFERENCE_EXCEPTION, "Object kindridGift of type Kindrid.KindridDonation is null!");
            return;
        }

        string strDonorTags = "";

        if (kindridGift != null && kindridGift.donor != null && kindridGift.donor.tags != null)
        {
            try
            {
                strDonorTags = JsonConvert.SerializeObject(kindridGift.donor.tags).ToString();
            }
            catch (Exception ex)
            {
                WriteWebHookError(KindridWebHookError.CANNOT_SERIALIZE_OBJECT, "Cannot serialize object.  Is the content a serializable object?  Message: " + ex.Message + "");
                return;
            }
        }

        
        // If we made it here, we can start executing processes like automation emails or 
        // database storage of the records (for reconciliation).  We're going to store first.        

        try
        {
            
            // Store the data in the database.
            // The implementation here utilizes a DataAccessLayer object with a singleton pattern to write 
            // the record to the database, and return the unique ID for that row (RowID).  

            string strRemoteAddr = Request.ServerVariables["REMOTE_ADDR"].ToString();

            DataAccessLayer DAL = DataAccessLayer.GetInstance();
            int intRowID = DAL.KindridDonationAdd(json, strRemoteAddr, kindridGift.status, kindridGift.amount, kindridGift.date, kindridGift.id,
                kindridGift.designation, kindridGift.to, kindridGift.donor.phone, kindridGift.donor.name, kindridGift.donor.address, kindridGift.donor.city,
                kindridGift.donor.state, kindridGift.donor.zip, kindridGift.donor.id, kindridGift.donor.email, strDonorTags, kindridGift.donor.tags._campus,
                kindridGift.source_type, kindridGift.giving_type, strKindridSignatureHeader, strDataGeneratedSignature);

            
            // Was there an error?
            if (DAL.ErrorFlag)
            {
                WriteWebHookError(KindridWebHookError.DATA_ACCESS_LAYER_ERROR, "DAL error. Save unsuccessful.  Message: " + DAL.DetailedMessage + "");
                return;
            }
            
            
            // This should always come last, so we can report any errors that may have happened.
            // There were no errors.  Write the success information as a response.
            
            WriteWebHookSuccess(intRowID);
            return;
        }
        catch (Exception ex)
        {
            WriteWebHookError(KindridWebHookError.GENERAL_ERROR, "General error. Save unsuccessful.  Message: " + ex.Message + "");
            return;
        }

    }
</script>