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
 * Comments will refer to 'The OAuth 1.0 Protocol'[1].
 *
 * [1] http://tools.ietf.org/rfc/rfc5849.txt
 */

/**
 * <pre>
 * val url = new URL("http://example.com/foo")
 * val urlConn = url.openConnection.asInstanceOf[HttpURLConnection]
 *
 * import com.jcraft.oaus.OAuthClient
 * val clientCredential = ClientCredential(CONSUMER_KEY, CONSUMER_SECRET)
 * val tokenCredential = TokenCredential(ACCESS_TOKEN, TOKEN_SECRET)
 * val oac = new OAuthClient(clientCredential)
 * oac.sign(rulConn, tokenCredential)
 * 
 * urlConn.connect
 * urlConn.getReponseCode
 * </pre>
 */ 
class OAuthClient(val clientCredential: ClientCredential) {

  import _root_.scala.collection.mutable.Map

  type Parameter = (String, String)

  var signature: Signature = HMACSHA1


  def signGetRequest(uri: String,
                     tokenCredential: TokenCredential)
                    (f: (String, String) => Unit): Unit = {
    sign(HTTPMethod.GET, uri, None, Some(tokenCredential), None)(f)
  } 

  def signPostRequest(uri: String, 
                      query_string: String,
                      tokenCredential: TokenCredential)
                     (f: (String, String) => Unit): Unit = {
    sign(HTTPMethod.POST, uri, Some(query_string), Some(tokenCredential), None)(f)
  } 

  def sign(method: HTTPMethod.Value,
           uri: String, 
           query_string: Option[String],
           tokenCredential: Option[TokenCredential],
           oauth_param_aux: Option[Seq[Parameter]]
          )(f: (String, String) => Unit): Unit = {

    val (base_uri, user_params) = normalize(uri, query_string)

    // The following protocol parameters are defined at "3.1.  Making Requests".
    val oauth_params = Map(
        "oauth_consumer_key" -> urlencoder(clientCredential.identifier),
	"oauth_token"-> tokenCredential.map(_.oauth_token).getOrElse(""),
        "oauth_signature_method" -> signature.methodName,
        "oauth_timestamp" -> (System.currentTimeMillis / 1000).toString,
        "oauth_nonce" -> java.util.UUID.randomUUID.toString,
        "oauth_version" -> "1.0")

    // If auxially protocol parameters(for example, "oauth_callback")
    // are given, they should be added to oauth_params.
    oauth_param_aux.foreach{ _.foreach { 
      case (k, v) => oauth_params += (k -> urlencoder(v) )
    }}

    // RFC5849 allows to send empty "oauth_token"(Appendix A) in requesting
    // temporary credentials, but Twitter must not accept it ;-(
    if(oauth_params("oauth_token") == "")
      oauth_params -= "oauth_token"


    // 3.4.1. Signature Base String
    val signatureBaseString = 
      method.toString + "&" +
      urlencoder(base_uri) + "&" +
      (sort((user_params ++ oauth_params).toSeq) map {       // Section 3.4.1.3.2
        case (k, v) => urlencoder(k) + "%3D" + urlencoder(v)
      } mkString "%26")

    val _signature= 
      signature(signatureBaseString,
                clientCredential,
                tokenCredential map { _.oauth_token_secret } getOrElse "")

    f("Authorization", 
      "OAuth " + ((oauth_params + ("oauth_signature" -> urlencoder(_signature))) map {
       case (k, v) => "%s=\"%s\"".format(k, v) 
      } mkString ","))
  }

  private def normalize(uri: String, query_string: Option[String]) = {
    import java.net.URI

    // 3.4.1.2.  Base String URI
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

    val _uri = new java.net.URI(uri)

    val query = if(_uri.getRawQuery == null) "" else _uri.getRawQuery

    (normalizeURL(_uri),
     // 3.4.1.3.1.  Parameter Sources
     // The parameters are from the query of URI and
     // from the HTTP request entity-body; query_string, in this case.
     // At the later step, the protcol parameters will be appended and be sorted.
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
   * 3.4.1.3.2.  Parameters Normalization
   * 2. The parameters are sorted by name, using ascending byte value
   *    ordering.  If two or more parameters share the same name, they
   *    are sorted by their value.
   */ 
  private def sort(s:Seq[Parameter]) = {
    def sorter(x: Parameter, y: Parameter): Boolean = 
      (x._1 < y._1) || ((x._1 == y._1) && x._2 < y._2)
    util.Sorting.stableSort(s, sorter _)
  }
}
