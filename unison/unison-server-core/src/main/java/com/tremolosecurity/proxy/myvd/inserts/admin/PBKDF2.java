/*
Copyright 2015 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


package com.tremolosecurity.proxy.myvd.inserts.admin;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;

public class PBKDF2
{
	
	public static String generateHash(String password) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		StringBuffer b = new StringBuffer();
		b.append("{myvd}");
		
		//generate salt
		SecureRandom sr = new SecureRandom();
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		
		b.append(new String(Base64.encode(salt))).append(':');
		
		byte[] hashed = deriveKey(password.getBytes("UTF-8"), salt, 10000, 32);
		
		b.append(new String(Base64.encode(hashed)));
		
		return b.toString();
		
	}
	
	public static boolean checkPassword(String password,String hashStr) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
		String salt64 = hashStr.substring(hashStr.indexOf('}') + 1,hashStr.indexOf(':'));
		byte[] salt = Base64.decode(salt64.getBytes("UTF-8"));
	
		String hash64 = hashStr.substring(hashStr.indexOf(':') + 1);
		byte[] hash = Base64.decode(hash64.getBytes("UTF-8"));
		
		byte[] check = deriveKey(password.getBytes("UTF-8"),salt,10000,32);
		
		if (hash.length != check.length) {
			return false;
		}
		
		for (int i=0;i<hash.length;i++) {
			if (hash[i] != check[i]) {
				return false;
			}
		}
		
		return true;
		
	}
	
	
    public static byte[] deriveKey( byte[] password, byte[] salt, int iterationCount, int dkLen )
        throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException
    {
        SecretKeySpec keyspec = new SecretKeySpec( password, "HmacSHA256" );
        Mac prf = Mac.getInstance( "HmacSHA256" );
        prf.init( keyspec );

        // Note: hLen, dkLen, l, r, T, F, etc. are horrible names for
        //       variables and functions in this day and age, but they
        //       reflect the terse symbols used in RFC 2898 to describe
        //       the PBKDF2 algorithm, which improves validation of the
        //       code vs. the RFC.
        //
        // dklen is expressed in bytes. (16 for a 128-bit key)

        int hLen = prf.getMacLength();   // 20 for SHA1
        int l = Math.max( dkLen, hLen); //  1 for 128bit (16-byte) keys
        int r = dkLen - (l-1)*hLen;      // 16 for 128bit (16-byte) keys
        byte T[] = new byte[l * hLen];
        int ti_offset = 0;
        for (int i = 1; i <= l; i++) {
            F( T, ti_offset, prf, salt, iterationCount, i );
            ti_offset += hLen;
        }

        if (r < hLen) {
            // Incomplete last block
            byte DK[] = new byte[dkLen];
            System.arraycopy(T, 0, DK, 0, dkLen);
            return DK;
        }
        return T;
    } 


    private static void F( byte[] dest, int offset, Mac prf, byte[] S, int c, int blockIndex ) {
        final int hLen = prf.getMacLength();
        byte U_r[] = new byte[ hLen ];
        // U0 = S || INT (i);
        byte U_i[] = new byte[S.length + 4];
        System.arraycopy( S, 0, U_i, 0, S.length );
        INT( U_i, S.length, blockIndex );
        for( int i = 0; i < c; i++ ) {
            U_i = prf.doFinal( U_i );
            xor( U_r, U_i );
        }

        System.arraycopy( U_r, 0, dest, offset, hLen );
    }

    private static void xor( byte[] dest, byte[] src ) {
        for( int i = 0; i < dest.length; i++ ) {
            dest[i] ^= src[i];
        }
    }

    private static void INT( byte[] dest, int offset, int i ) {
        dest[offset + 0] = (byte) (i / (256 * 256 * 256));
        dest[offset + 1] = (byte) (i / (256 * 256));
        dest[offset + 2] = (byte) (i / (256));
        dest[offset + 3] = (byte) (i);
    } 

    // ctor
    private PBKDF2 () {}

}