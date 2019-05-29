/*
Copyright 2018 Tremolo Security, Inc.

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

package com.tremolosecurity.prometheus.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import org.apache.commons.codec.binary.Base64;

public class PrometheusUtils {
    public static String compress(String unzipped) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
				
        GZIPOutputStream compressor  = new GZIPOutputStream(baos);
        
        try {
            compressor.write(unzipped.getBytes("UTF-8"));
            compressor.flush();
            compressor.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
            e.printStackTrace();
            return "";
		}


        return Base64.encodeBase64String(baos.toByteArray());
    }

    public static String decompress(String zipped) throws IOException {
        byte[] compressedData = Base64.decodeBase64(zipped);
		ByteArrayInputStream bin = new ByteArrayInputStream(compressedData);
		
		GZIPInputStream decompressor  = new GZIPInputStream(bin);
		//decompressor.setInput(compressedData);
		
		// Create an expandable byte array to hold the decompressed data
		ByteArrayOutputStream bos = new ByteArrayOutputStream(compressedData.length);
		
		// Decompress the data
		byte[] buf = new byte[1024];
		int len;
    
        while ((len = decompressor.read(buf)) > 0) {
        
            
            bos.write(buf, 0, len);
        
        }
        bos.close();
    

		// Get the decompressed data
		byte[] decompressedData = bos.toByteArray();
		
		return new String(decompressedData);
    }
}