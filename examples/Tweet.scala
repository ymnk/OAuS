/**
Copyright (c) 2010 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.

   3. The names of the authors may not be used to endorse or promote products
      derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
*/
import java.net._ 
import com.jcraft.oaus.{OAuthClient, ClientCredential, TokenCredential}

object Tweet{

  val CONSUMER_KEY    = ""
  val CONSUMER_SECRET = ""
  val ACCESS_TOKEN = "" 
  val TOKEN_SECRET = ""

  def main(arg:Array[String]){

    if(CONSUMER_KEY == "")
      error("The consumer_key is not given.")

    val tweet = java.net.URLEncoder.encode("Hello "+(new java.util.Date), "UTF-8")

    val url = "http://api.twitter.com/1/statuses/update.xml"
    val urlConn = new URL(url).openConnection.asInstanceOf[HttpURLConnection]
    urlConn.setRequestMethod("POST")     
    urlConn.setDoOutput(true);

    val clientCredential = ClientCredential(CONSUMER_KEY, CONSUMER_SECRET)
    val tokenCredential = TokenCredential(ACCESS_TOKEN, TOKEN_SECRET)
    val oac = new OAuthClient(clientCredential)

    oac.signPostRequest(urlConn.getURL.toString,
                        "status="+tweet, 
                        tokenCredential){
      (k, v) => urlConn.setRequestProperty(k, v)
    }

    val writer = new java.io.PrintWriter(urlConn.getOutputStream)
    writer.print("status="+tweet)
    writer.close()

    println(urlConn.getResponseCode)
    println(xml.XML.load(urlConn.getInputStream))
  } 
}
