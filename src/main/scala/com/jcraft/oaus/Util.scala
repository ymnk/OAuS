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

/** 
 * Comments will refer to 'The OAuth 1.0 Protocol'[1].
 *
 * [1] http://tools.ietf.org/rfc/rfc5849.txt
 */

private object Util {

  /**
   * 3.6 Percent Encoding
   * Characters in the unreserved character set as defined by [RFC3986],
   * Section 2.3 (ALPHA, DIGIT, "-", ".", "_", "~") MUST NOT be encoded.
   * URLEncoder will encode ' ' to '+', and '~' to '%7E',
   * and will not encode '*', unfortunately.
   */ 
  val urlencoder = 
    (s:String) => java.net.URLEncoder.encode(s, "UTF-8").
                                      replace ("*", "%42").
                                      replace ("+", "%20").
                                      replace ("%7E", "~")

  val urldecoder = 
    (s:String) => java.net.URLDecoder.decode(s, "UTF-8")


  val b64encoder = Base64.encode _

  // The following code is from JSch(http://www.jcraft.com/jsch/).
  private object Base64{
    val b64 = 
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".getBytes

    def encode(buf:Array[Byte]) = {
      val tmp = new Array[Byte](buf.length*2)
      var i:Int = 0
      var j:Int = 0
      var k:Int = 0
    
      var foo = (buf.length/3)*3;

      i=0; j=0;
      while(j<foo){
        k=(buf(j)>>>2)&0x3f
        tmp(i)=b64(k); i += 1
        k=(buf(j)&0x03)<<4|(buf(j+1)>>>4)&0x0f
        tmp(i)=b64(k); i += 1
        k=(buf(j+1)&0x0f)<<2|(buf(j+2)>>>6)&0x03
        tmp(i)=b64(k); i += 1
        k=buf(j+2)&0x3f;
        tmp(i)=b64(k); i += 1
        j += 3
      }

      foo=buf.length-foo;

      if(foo==1){
        k=(buf(j)>>>2)&0x3f;
        tmp(i)=b64(k); i += 1
        k=((buf(j)&0x03)<<4)&0x3f;
        tmp(i)=b64(k); i += 1
        tmp(i)='='; i += 1
        tmp(i)='='; i += 1
      }
      else if(foo==2){
        k=(buf(j)>>>2)&0x3f;
        tmp(i)=b64(k); i += 1
        k=(buf(j)&0x03)<<4|(buf(j+1)>>>4)&0x0f;
        tmp(i)=b64(k); i += 1
        k=((buf(j+1)&0x0f)<<2)&0x3f;
        tmp(i)=b64(k); i += 1
        tmp(i)='='; i += 1
      }

      val bar=new Array[Byte](i);
      System.arraycopy(tmp, 0, bar, 0, i);
      bar
    }
  }
}
