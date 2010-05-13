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

import _root_.com.jcraft.oaus.Util.{b64encoder, urlencoder, urldecoder}

/**
 * Comments will refer to 'The OAuth 1.0 Protocol'[1].
 *
 * [1] http://tools.ietf.org/rfc/rfc5849.txt
 */ 

trait Signature {
  def methodName: String

  def apply(signatureBaseString: String, 
            consumer_secret: String,
            key: String): String

  protected def toString(buf: Array[Byte]) = new String(b64encoder(buf))
}

// 3.4.2.  HMAC-SHA1
object HMACSHA1 extends Signature {
  import javax.crypto._

  val methodName = "HMAC-SHA1"

  def apply(signatureBaseString: String, 
            consumerSecret: String,
            key: String): String = {
    val SHA1 = "HmacSHA1"
    val mac = Mac.getInstance(SHA1)
    val _key = (urlencoder(consumerSecret) + "&" + urlencoder(key)).getBytes("UTF-8")
    mac.init(new spec.SecretKeySpec(_key, SHA1))
    toString(mac.doFinal(signatureBaseString.getBytes("UTF-8")))
  }
} 

// 3.4.4.  PLAINTEXT
object PLAINTEXT extends Signature {

  val methodName = "PLAINTEXT"

  def apply(signatureBaseString: String, 
            consumerSecret: String,
            key: String): String = {
    urlencoder(consumerSecret) + "&" + urlencoder(key)
  }
} 
