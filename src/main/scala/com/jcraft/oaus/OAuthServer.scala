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
package com.jcraft.oaus

import java.net.{URL, HttpURLConnection}
import scala.io.Source.fromInputStream

/** 
 * Comments will refer to 'The OAuth 1.0 Protocol'[1].
 *
 * [1] http://tools.ietf.org/rfc/rfc5849.txt
 */

trait OAuthServer {

  // 2. Redirection-Based Authorization
  def temporaryCredentialRequestURI: String 
  def resourceOwnerAuthorizationURI: String 
  def tokenRequestURI: String 

  // 2.1. Temporary Credentials
  def requestTemporaryCredential(c: OAuthClient): TemporaryCredential = 
    requestTemporaryCredential(c, "oob")  // out-of-band as callback, by the default.

  def requestTemporaryCredential(c: OAuthClient, 
                                 call_back:String): TemporaryCredential = {
    var urlConn = 
      new URL(temporaryCredentialRequestURI).openConnection.
        asInstanceOf[HttpURLConnection]

    urlConn.setRequestMethod("POST")     
    urlConn.setDoOutput(true);

    c.sign(HTTPMethod("POST"), 
           temporaryCredentialRequestURI,
           None,
           None,
           Some(List("oauth_callback" -> call_back))) {
      (k, v) => urlConn.setRequestProperty(k, v)
    }

    urlConn.getResponseCode match{
      case 200 =>
        val response = 
          fromInputStream(urlConn.getInputStream, "UTF-8").getLines mkString ""
        val map = response2Map(response) 
        TemporaryCredential(map("oauth_token"), map("oauth_token_secret"))
      case c => 
        val message = urlConn.getHeaderField("WWW-Authenticate")
        error(c+" "+message)
    }

  }

  // 2.2.  Resource Owner Authorization
  def authorizationURI(tmpc:TemporaryCredential) = 
    resourceOwnerAuthorizationURI+"?oauth_token="+tmpc.oauth_token

  // 2.3. Token Credentials
  def tokenCredential(c: OAuthClient, tmpc:TemporaryCredential, verifier:String) = {
    var urlConn = new URL(tokenRequestURI).openConnection.asInstanceOf[HttpURLConnection]
    urlConn.setRequestMethod("POST")     
    urlConn.setDoOutput(true);

    val tknc = TokenCredential(tmpc.oauth_token, tmpc.oauth_verifier)

    c.sign(HTTPMethod("POST"), 
           tokenRequestURI, 
           None,
	   Some(tknc),
           Some(List(("oauth_verifier" -> (verifier.trim))))) {
      (k, v) => urlConn.setRequestProperty(k, v)
    }

    urlConn.getResponseCode match{
      case 200 =>
        val response = 
          fromInputStream(urlConn.getInputStream, "UTF-8").getLines mkString ""
        val map = response2Map(response) 
        TokenCredential(map("oauth_token"), map("oauth_token_secret"))
      case c => 
        val message = urlConn.getHeaderField("WWW-Authenticate")
        error(c+" "+message)
    }
  }

  private def response2Map(response:String): Map[String, String] = 
    response.split("&").foldLeft(Map[String,String]()){ case (s, v) => 
      s + {v.split("=") match {case Array(k, v) => (k, v)}}
  }
}

object Twitter extends OAuthServer {
  val temporaryCredentialRequestURI = "http://twitter.com/oauth/request_token"
  val resourceOwnerAuthorizationURI = "http://twitter.com/oauth/authorize"
  val tokenRequestURI = "https://twitter.com/oauth/access_token"
}

object Foursquare extends OAuthServer {
  val temporaryCredentialRequestURI = "http://foursquare.com/oauth/request_token"
  val resourceOwnerAuthorizationURI = "http://foursquare.com/oauth/authorize"
  val tokenRequestURI = "http://foursquare.com/oauth/access_token"
}

object YahooCom extends OAuthServer {
  val temporaryCredentialRequestURI = "https://api.login.yahoo.com/oauth/v2/get_request_token"
  val resourceOwnerAuthorizationURI = "https://api.login.yahoo.com/oauth/v2/request_auth"
  val tokenRequestURI = "https://api.login.yahoo.com/oauth/v2/get_token"
}

object YahooCoJp extends OAuthServer {
  val temporaryCredentialRequestURI = "https://auth.login.yahoo.co.jp/oauth/v2/get_request_token"
  val resourceOwnerAuthorizationURI = "https://auth.login.yahoo.co.jp/oauth/v2/request_auth"
  val tokenRequestURI = "https://auth.login.yahoo.co.jp/oauth/v2/get_token"
}
