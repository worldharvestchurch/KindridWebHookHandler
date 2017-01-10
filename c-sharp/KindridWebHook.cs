/* ----------------------------------------------------------------------------- 
 * Kindrid C# Request Model
 * 
 * version:   1.0 
 * date:      2017-01-04
 * author:    Jay Baldwin IV
 * copyright: (C) 2017 World Harvest Church.  
 * 
 * There are no guarantees or warrantees associated with downloading or using this code. 
 * It is free to use with Kindrid account for anyone.  
 * 
 * version history: 
 * 
 * DATE         AUTHOR     CHANGES
 * 2017-01-04   JJBIV      Initial version
 * ----------------------------------------------------------------------------- 
 * 
 * This module was made to work with Kindrid's Webhook implementation.
 * 
 * Dependencies: Json.NET from Newtonsoft
 * 
 * Retrieve your API secret from here: https://kindrid.com/dashboard/settings/api 
 * 
 * On that page, you can also specify your Webhook URL.  
 * 
 * Documentation available below.  Sample Data available at the bottom of the file.
 * 
 * Documentation was written from information available at kindrid's webhooks apiary
 * page: http://docs.kindridwebhooks.apiary.io/#introduction/example-request-body
 * 
 * Pulled 1/3/2017
 * 
 * -----------------------------------------------------------------------------*/

/* Get the Request JSON
 * ----------------------------------------------------------------------------- 
 * 
 * All requests from Kindrid will be sent via POST, with the data JSON encoded in 
 * the body of the request. 
 * 
 * For instance, rather than accessing a POST variable, you will need to retrieve the 
 * entirety of the POST request, like this:
 * 
 * [C# code]
              
   // Build a variable to hold the JSON encoded request
   string strRawBody = (new StreamReader(Request.InputStream)).ReadToEnd();
              
 * [/C# code]
 * 
 * -----------------------------------------------------------------------------*/

/* Webhook Security
 * -----------------------------------------------------------------------------
 * 
 * 
 * Each request will also be signed via HMAC-SHA1, and the signature will be sent in 
 * Request header as X-Kindrid-Signature.
 * 
 * [C# code]
             
   // This variable will hold the X-Kindrid-Signature as sent from Kindrid.
   string strKindridSignatureHeader = "";
   if (Request.Headers["X-Kindrid-Signature"] != null) strKindridSignatureHeader = Request.Headers["X-Kindrid-Signature"].ToString();
                
 * [/C# code]
 * 
 * To verify that Kindrid sent the webhook, verify the signature. To do this, 
 * Take the full URL of the request and concatenate the raw body to the end of the URL, 
 * before parsing the JSON document.  The JSON document should not contain any leading 
 * or trailing whitespace.Create an HMAC-SHA1 signature using the API secret 
 * (you can find the API secret on your Kindrid dashboard) as the key. 
 * 
 * For example:
 * 
 * If your Webhook URL is https://example.com/endpoint
 * 
 * [C# code]
               
   // Build a variable to hold the absolute path to this WebHook File 
   // using the Fully Qualified URL domain and a complete https|http request.
   string strWebHookURL = "https://example.com/endpoint";
               
   // Build a variable to hold the JSON encoded request
   string strRawBody = (new StreamReader(Request.InputStream)).ReadToEnd();
               
   // Build the string to check the HMAC with.
   string strSecurityCheck = strWebHookURL + strRawBody;
               
   // The value of strSecurityCheck will look something like this:
   // https://example.com/endpoint{"donation":{"status"...
                   
 * [/C# code]
 * 
 * Use this string and your API secret as the key to generate the HMAC SHA-1.
 * For example:
 * 
 * [C# code]
              
   public string GenerateHMACSHA1(string data, string key)
   {
       Encoding enc = Encoding.ASCII;
       HMACSHA1 hmac = new HMACSHA1(enc.GetBytes(key));
       hmac.Initialize();
    
       byte[] buffer = enc.GetBytes(data);
       return BitConverter.ToString(hmac.ComputeHash(buffer)).Replace("-", "").ToLower();
   }
              
   // ...
                
   // Build a variable to hold the API key
   string strApiSecret = "KINDRID_API_KEY";
                
   // Build a variable to hold the HMACSHA-1 signature
   string strDataGeneratedSignature = GenerateHMACSHA1(strSecurityCheck, strApiSecret);
                
   // True if the signatures match.  Otherwise false. 
   bool blnSignaturesMatch = (strKindridSignatureHeader == strDataGeneratedSignature);
             
   // If blnSignaturesMatch == true, you are safe to write the data - the signatures 
   // matched!
                  
 * [/C# code]
 * 
 * -----------------------------------------------------------------------------*/

using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace Kindrid
{
    public static class KindridSignatureVerification
    {
        /// <summary>
        /// Returns an HMACSHA1 signature of strUrlAndRequest using strApiSecret as the key
        /// </summary>
        /// <param name="strUrlAndRequest">Concatenated string of WebHook URL and raw body of the request.</param>
        /// <param name="strApiSecret">API Secret to be used as the key in the HMACSHA-1 encode.</param>
        /// <returns></returns>
        public static string HMACSHA1(string strUrlAndRequest, string strApiSecret)
        {
            Encoding ascii = Encoding.ASCII;

            HMACSHA1 hmac = new HMACSHA1(ascii.GetBytes(strApiSecret));
            hmac.Initialize();

            byte[] data = ascii.GetBytes(strUrlAndRequest);
            byte[] hash = hmac.ComputeHash(data);

            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }

    public class KindridJson
    {
        public KindridDonation donation { get; set; }
    }

    public class KindridDonation
    {
        /// <summary>
        /// Records will hold a value of "completed" if the transaction was 
        /// successful and funds were captured.
        /// </summary>
        [DefaultValue("")]
        public string status { get; set; }

        /// <summary>
        /// The amount of the donation to be credited to the donor.  
        /// </summary>
        [DefaultValue(0.0)]
        public decimal amount { get; set; }

        /// <summary>
        /// The date/time of the transaction in ISO 8601 Format E8601DTw.d.  
        /// Real example value: 2017-01-04T20:08:57.579000 
        /// </summary>
        [DefaultValue("")]
        public string date { get; set; }

        /// <summary>
        /// The unique string ID assigned to this transaction by Kindrid.
        /// </summary>
        [DefaultValue("")]
        public string id { get; set; }

        /// <summary>
        /// If designated giving is used in Kindrid, this value will be a string.  
        /// May be empty/null if not specified.
        /// </summary>
        [DefaultValue("")]
        public string designation { get; set; } // can be null

        /// <summary>
        /// The number or keyword/shortcode was this gift given through.
        /// </summary>
        [DefaultValue("")]
        public string to { get; set; }

        /// <summary>
        /// Text Giving or Other?
        /// </summary>
        [DefaultValue("")]
        public string giving_type { get; set; }

        /// <summary>
        /// Specified whether the gift came through as a credit card or ACH transaction.
        /// </summary>
        [DefaultValue("")]
        public string source_type { get; set; }

        public KindridDonor donor { get; set; }
    }


    /// <summary>
    /// Object representing information about a Kindrid donor/giver.  
    /// </summary>
    public class KindridDonor
    {
        public void KindredDonor()
        {
            tags = new KindridTagSet();
        }

        /// <summary>
        /// Contains the entire portion of the name.  No data validation is present. Will include 
        /// first name, middle initial or name, and last name.  Suffix possible.
        /// </summary>
        [DefaultValue("")]
        public string name { get; set; }

        /// <summary>
        /// The donor's address, either Number and Street, or the entire record.  Some records 
        /// in our experience came through with City, State, and Zip as well, instead of 
        /// having that information broken into the separate fields.
        /// </summary>
        [DefaultValue("")]
        public string address { get; set; }

        /// <summary>
        /// THe donor's city.  May be empty/null if not specified.
        /// </summary>
        [DefaultValue("")]
        public string city { get; set; }

        /// <summary>
        /// The donor's state.  May be empty/null if not specified.
        /// </summary>
        [DefaultValue("")]
        public string state { get; set; }

        /// <summary>
        /// The donor's zip code.  May be empty/null if not specified.
        /// </summary>
        [DefaultValue("")]
        public string zip { get; set; }

        /// <summary>
        /// Unique ID Kindrid associates with the donor in their system.  Will help you
        /// identify individual donor records in Kindrid's system in the future.
        /// </summary>
        [DefaultValue("")]
        public string id { get; set; }

        /// <summary>
        /// The donor's email address.  This is where Kindrid sends e-receipts.  
        /// </summary>
        [DefaultValue("")]
        public string email { get; set; }

        /// <summary>
        /// The donor's CELL phone number... the line that originated the SMS.
        /// </summary>
        [DefaultValue("")]
        public string phone { get; set; }

        public KindridTagSet tags { get; set; }
    }


    /// <summary>
    /// Tags associated with the Kindrid donor/giver, such as Campus.
    /// </summary>
    public class KindridTagSet
    {
        /// <summary>
        /// Campus ID for the campus selected in Kindrid.  May be empty/null if not specified. 
        /// </summary>
        [DefaultValue("")]
        public string _campus { get; set; } // can be null
        //public string campus { get; set; } // This was in the documentation, but wasn't actually used.
        //public string chms_id { get; set; } // This was in the documentation, but wasn't actually used.
    }
}



/*
// This is what Kindrid says they send:
    
        {
            "donation": {
                "status": "completed",
                "amount": 12.12,
                "date": "2013-10-14T08:42:27Z",
                "id": "xxxxSAMPLEIDxxxx",
                "designation": "missions",
                "to": "+17705551212",
                "donor": {
                    "name": "Sample Name",
                    "address": "123 Main St",
                    "city": "Anytown",
                    "state": "ST",
                    "zipcode": "12345",
                    "id": "xxxxSAMPLEIDxxxx",
                    "email": "email@address.smp",
                    "phone": "+16265551212",
                    "zip": "12345",
                    "tags": {
                        "campus": "Campus Name",
                        "chms_id": "1234"
                    }
                }
            }
        }
     
     
 // This is what Kindrid really sends:
        {
            "donation": {
                "status": "completed",
                "amount": 12.12,
                "date": "2013-10-14T08:42:27Z",
                "id": "xxxxSAMPLEIDxxxx",
                "designation": "missions",
                "to": "+17705551212",
                "giving_type": "Text Giving",
                "source_type": "Card",
                "donor": {
                    "name": "Sample Name",
                    "address": "123 Main St",
                    "city": "Anytown",
                    "state": "ST",
                    "zipcode": "12345",
                    "id": "xxxxSAMPLEIDxxxx",
                    "email": "email@address.smp",
                    "phone": "+16265551212",
                    "zip": "12345",
                    "tags": {
                        "_campus": "58629938b5ef8a00019b721f"
                    }
                }
            }
        }
     
 // This is how it would come through:
        { "donation": { "status": "completed", "amount": 12.12, "date": "2013-10-14T08:42:27Z", "id": "xxxxSAMPLEIDxxxx", "designation": "missions", "to": "+17705551212", "donor": { "name": "Sample Name", "address": "123 Main St", "city": "Anytown", "state": "ST", "zipcode": "12345", "id": "xxxxSAMPLEIDxxxx", "email": "email@address.smp", "phone": "+16265551212", "zip": "12345", "tags": { "campus": "Campus Name", "chms_id": "1234" } } } }
 */