package com.tremolosecurity.provisioning.workflows;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;

import org.openapi4j.core.exception.ResolutionException;
import org.openapi4j.core.validation.ValidationException;
import org.openapi4j.parser.OpenApi3Parser;
import org.openapi4j.parser.model.v3.OpenApi3;
import org.openapi4j.schema.validator.v3.SchemaValidator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


public class WorkflowYamlUtils {

	OpenApi3 api;
	JsonNode schemaRoot;
	
	public WorkflowYamlUtils() throws ResolutionException, ValidationException, IOException {
		URL pathToSchema = getClass().getClassLoader().getResource("workflowtasks-openapi.json");
		ObjectMapper objectMapper = new ObjectMapper();
		schemaRoot = objectMapper.readTree(pathToSchema);
		
	}
	
	public boolean isValidWorkflowTasks(String json) throws UnsupportedEncodingException, IOException, ResolutionException {
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode root = objectMapper.readTree(json.getBytes("UTF-8"));
		SchemaValidator schemaValidator = new SchemaValidator(null, schemaRoot);
		
		try {
		    schemaValidator.validate(root);
		} catch(ValidationException ex) {
		    ex.printStackTrace();
		    return false;
		}
		
		return true;
	}
}
