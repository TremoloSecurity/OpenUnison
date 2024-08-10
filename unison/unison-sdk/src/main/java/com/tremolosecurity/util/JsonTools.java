package com.tremolosecurity.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;



import com.cedarsoftware.io.JsonReader;
import com.cedarsoftware.io.JsonWriter;
import com.cedarsoftware.io.ReadOptions;
import com.cedarsoftware.io.ReadOptionsBuilder;

public class JsonTools {
	
	public static String writeObjectToJson(Object o) {
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonWriter jw = new JsonWriter(baos);
		jw.write(o);
		jw.close();
		return new String(baos.toByteArray());
	}
	
	public static Object readObjectFromJson(String json)  {
		if (json.startsWith("\"")) {
			// json is just a string in quotes
			return json.substring(1,json.length() - 1);
		}
		
		
		ByteArrayInputStream bais = null;
		try {
			bais = new ByteArrayInputStream(json.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// do nothing
		}
		JsonReader jr = new JsonReader(bais,ReadOptionsBuilder.getDefaultReadOptions());
		return jr.readObject(Object.class);
	}
	
	public static String readStringFromJson(String json)  {
		ByteArrayInputStream bais = null;
		try {
			bais = new ByteArrayInputStream(json.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// do nothing
		}
		JsonReader jr = new JsonReader(bais,ReadOptionsBuilder.getDefaultReadOptions());
		return jr.readObject(String.class);
	}
	
	public static Map jsonToMap(String json) {
		ByteArrayInputStream bais = null;
		try {
			bais = new ByteArrayInputStream(json.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// do nothing
		}
		JsonReader jr = new JsonReader(bais,ReadOptionsBuilder.getDefaultReadOptions());
		return jr.readObject(Map.class);
	}
}
