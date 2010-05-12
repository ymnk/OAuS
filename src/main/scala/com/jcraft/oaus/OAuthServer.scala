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

trait OAuthServer {

  def requestTokenURL: String 

  def authorizationURL: String 

  def accessTokenURL: String 

  def requestToken(c: OAuthClient): RequestToken = requestToken(c, "oob")

  def requestToken(c: OAuthClient, call_back:String): RequestToken = {
    var urlConn = new URL(requestTokenURL).openConnection.asInstanceOf[HttpURLConnection]
    urlConn.setRequestMethod("POST")     
    urlConn.setDoOutput(true);

    c.sign(HTTPMethod("POST"), 
           requestTokenURL, 
           None,
           Some(List("oauth_callback" -> call_back)),
           None) {
      (k, v) => urlConn.setRequestProperty(k, v)
    }

    urlConn.getResponseCode match{
      case 200 =>
        val response = 
          fromInputStream(urlConn.getInputStream, "UTF-8").getLines mkString ""
        val map = response2Map(response) 
        new RequestToken(map("oauth_token"), map("oauth_token_secret"))
      case c => 
        val message = urlConn.getHeaderField("WWW-Authenticate")
        error(c+" "+message)
    }

  }

  def accessToken(c: OAuthClient, requestToken:RequestToken, verifier:String) = {
    var urlConn = new URL(accessTokenURL).openConnection.asInstanceOf[HttpURLConnection]
    urlConn.setRequestMethod("POST")     
    urlConn.setDoOutput(true);

    c.sign(HTTPMethod("POST"), 
           accessTokenURL, 
           None,
           Some(List(("oauth_verifier" -> (verifier.trim)))),
	   Some((requestToken.oauth_token, requestToken.oauth_token_secret))) {
      (k, v) => urlConn.setRequestProperty(k, v)
    }

    urlConn.getResponseCode match{
      case 200 =>
        val response = 
          fromInputStream(urlConn.getInputStream, "UTF-8").getLines mkString ""
        val map = response2Map(response) 
        new RequestToken(map("oauth_token"), map("oauth_token_secret"))
      case c => 
        val message = urlConn.getHeaderField("WWW-Authenticate")
        error(c+" "+message)
    }
  }

  private def response2Map(response:String): Map[String, String] = 
    response.split("&").foldLeft(Map[String,String]()){ case (s, v) => 
      s + {v.split("=") match {case Array(k, v) => (k, v)}}
  }

  class RequestToken(val oauth_token: String, val oauth_token_secret: String)

  def authorizeURL(requestToken:RequestToken) = 
    authorizationURL+"?oauth_token="+requestToken.oauth_token
}

object Twitter extends OAuthServer {
  val requestTokenURL = "http://twitter.com/oauth/request_token"
  val authorizationURL = "http://twitter.com/oauth/authorize"
  val accessTokenURL = "https://twitter.com/oauth/access_token"
}

object Foursquare extends OAuthServer {
  val requestTokenURL = "http://foursquare.com/oauth/request_token"
  val authorizationURL = "http://foursquare.com/oauth/authorize"
  val accessTokenURL = "http://foursquare.com/oauth/access_token"
}

object YahooCom extends OAuthServer {
  val requestTokenURL = "https://api.login.yahoo.com/oauth/v2/get_request_token"
  val authorizationURL = "https://api.login.yahoo.com/oauth/v2/request_auth"
  val accessTokenURL = "https://api.login.yahoo.com/oauth/v2/get_token"
}

object YahooCoJp extends OAuthServer {
  val requestTokenURL = "https://auth.login.yahoo.co.jp/oauth/v2/get_request_token"
  val authorizationURL = "https://auth.login.yahoo.co.jp/oauth/v2/request_auth"
  val accessTokenURL = "https://auth.login.yahoo.co.jp/oauth/v2/get_token"
}
