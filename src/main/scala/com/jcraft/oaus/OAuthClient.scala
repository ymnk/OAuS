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

import _root_.java.net.{URL, HttpURLConnection}
import _root_.com.jcraft.oaus.Util.{urlencoder, urldecoder}

/**
 * <pre>
 * val url = new URL("http://example.com/foo")
 * val urlConn = url.openConnection.asInstanceOf[HttpURLConnection]
 *
 * import com.jcraft.oaus.OAuthClient
 * val consumer = new OAuthClient(CONSUMER_KEY, CONSUMER_SECRET)
 * consumer.sign(rulConn, ACCESS_TOKEN, TOKEN_SECRET)
 * 
 * urlConn.connect
 * urlConn.getReponseCode
 * </pre>
 * 
 * Comments will refer to 'OAuth Core 1.0'[1].
 *
 * [1] http://oauth.net/core/1.0/
 */ 

class OAuthClient(val consumer_key: String, 
                  val consumer_secret: String){

  import _root_.scala.collection.mutable.Map

  type Credential = (String, String)
  type Parameter = (String, String)

  var signature: Signature = HMACSHA1


  def signGetRequest(url: String, 
                     access_token: String, token_secret: String 
                    )(f: (String, String) => Unit): Unit = {
    sign(HTTPMethod.GET, url, None, None, Some((access_token, token_secret)))(f)
  } 

  def signPostRequest(url: String, 
                      query_string: String,
                      access_token: String, token_secret: String 
                     )(f: (String, String) => Unit): Unit = {
    sign(HTTPMethod.POST, url, Some(query_string), None, Some((access_token, token_secret)))(f)
  } 

  def sign(method: HTTPMethod.Value,
           url: String, 
           query_string: Option[String],
           oauth_param_aux: Option[Seq[Parameter]],
           token: Option[Credential]
          )(f: (String, String) => Unit): Unit = {

    val (base_url, user_params) = normalize(url, query_string)

    /**
     * "7. Accessing ProtectedResources" has defined following parameters.
     */ 

    val oauth_params = Map(
        "oauth_consumer_key" -> urlencoder(consumer_key),
        "oauth_signature_method" -> signature.methodName,
        "oauth_timestamp" -> (System.currentTimeMillis / 1000).toString,
        "oauth_nonce" -> java.util.UUID.randomUUID.toString,
        "oauth_version" -> "1.0",       // Optional
	"oauth_token"-> token.map(_._1).getOrElse(""))

    oauth_param_aux.foreach{ _.foreach { 
      case (k, v) => oauth_params += (k -> urlencoder(v) )
    }}

    if(oauth_params("oauth_token")=="")
      oauth_params -= "oauth_token"


    /**
     * 9.1.3. Concatenate Request Elements
     */ 
    val signature_base_string = 
      method.toString + "&" +
      urlencoder(url) + "&" +
      (sort((user_params ++ oauth_params).toSeq) map {
        case (k, v) => urlencoder(k) + "%3D" + urlencoder(v)
      } mkString "%26")

    val _signature= 
      signature(signature_base_string, 
                consumer_secret, 
                token map { _._2 } getOrElse "")

    f("Authorization", 
      "OAuth " + ((oauth_params + ("oauth_signature" -> urlencoder(_signature))) map {
       case (k, v) => "%s=\"%s\"".format(k, v) 
      } mkString ","))
  }

  private def normalize(url: String, query_string: Option[String]) = {
    import java.net.URI

    def normalizeURL(uri: URI) = {
      val scheme = uri.getScheme.toLowerCase
      val port = uri.getPort
      val authority = uri.getAuthority.toLowerCase match {
        case authority if((port == 80 && scheme == "http") ||
                          (port == 443 && scheme == "https")) =>
          authority.substring(0, authority.lastIndexOf(":"))
        case authority => authority
      }
      val path = uri.getRawPath match {
        case "" => "/"
        case p => p
      }

      scheme + "://" + authority + path
    }

    val uri = new java.net.URI(url)
    val query = if(uri.getRawQuery == null) "" else uri.getRawQuery

    (normalizeURL(uri),
     (query + "&" + query_string.getOrElse("")).
        split("&").
        filter(s => { s != "" }).
        foldLeft(Set[Parameter]()){
          case (s, v) => s + {v.split("=") match{
            case Array(k) => (urldecoder(k) ->"")
            case Array(k,v) => (urldecoder(k) -> urldecoder(v))
          }}
        } map { case (k,v)=>(urlencoder(k), urlencoder(v)) }
    )

  }

  /**
   * 9.1.1 Normalize Request Parameters
   * If two or more parameters share the same name, they are sorted by their value.
   */ 
  private def sort(s:Seq[Parameter]) = {
    def sorter(x: Parameter, y: Parameter): Boolean = 
      (x._1 < y._1) || ((x._1 == y._1) && x._2 < y._2)
    util.Sorting.stableSort(s, sorter _)
  }
}
