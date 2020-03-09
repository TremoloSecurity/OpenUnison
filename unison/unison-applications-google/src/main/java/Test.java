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


import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Tokeninfo;
import com.google.api.services.oauth2.model.Userinfoplus;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.PlusScopes;


public class Test {

	/** Global instance of the JSON factory. */
	  private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	
	public static void main(String[] args) throws Exception {
		/*HttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
		JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();

		ArrayList<String> scopes = new ArrayList<String>();
		scopes.add(com.google.api.services.admin.directory.DirectoryScopes.ADMIN_DIRECTORY_USER);
		scopes.add(com.google.api.services.admin.directory.DirectoryScopes.ADMIN_DIRECTORY_ORGUNIT);
		
		GoogleCredential credential = new GoogleCredential.Builder().setTransport(httpTransport)
			    .setJsonFactory(jsonFactory)
			    .setServiceAccountId("61432502161-bgq2r6vtdefgqsco0i5pjrrpfe8f0dep@developer.gserviceaccount.com")
			    .setServiceAccountScopes(scopes)
			    .setServiceAccountUser("administrator@tremolosecurity-test.com")
			    .setServiceAccountPrivateKeyFromP12File(new File("/Users/mlb/Downloads/TestMyVD-0cf017d369c9.p12"))   
			    .build();
		
		
		
	    Directory service = new Directory.Builder(httpTransport, jsonFactory, credential)
        .setApplicationName("TestMyVD")
        .build();
	    
	   
	    
	    List<User> allUsers = new ArrayList<User>();
	    Directory.Users.List request = service.users().list().setCustomer("my_customer");
	    System.out.println(request);
	    do {
	        try {
	          Users currentPage = request.execute();
	          allUsers.addAll(currentPage.getUsers());
	          request.setPageToken(currentPage.getNextPageToken());
	        } catch (IOException e) {
	          System.out.println("An error occurred: " + e);
	          request.setPageToken(null);
	        }
	      } while (request.getPageToken() != null &&
	               request.getPageToken().length() > 0 );

	      // Print all users
	      for (User currentUser : allUsers) {
	    	  
	        System.out.println(currentUser);
	    	  
	      }
	      
	      List<User> searchRes = new ArrayList<User>();*/
	  	
	      
		
	}
	
	

}
