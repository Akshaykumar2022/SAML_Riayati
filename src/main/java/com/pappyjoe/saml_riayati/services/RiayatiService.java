package com.pappyjoe.saml_riayati.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pappyjoe.saml_riayati.SamlAttribute;
import com.pappyjoe.saml_riayati.SamlGenerator2;
import com.pappyjoe.saml_riayati.models.dtos.SsoLauncherDto;
import com.pappyjoe.saml_riayati.models.dtos.TokenResponseDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

@Service
public class RiayatiService {

    private final SamlGenerator2 samlGenerator;

    public RiayatiService(SamlGenerator2 samlGenerator) {
        this.samlGenerator = samlGenerator;
    }

    @Value("${riayati.token.url}")
    private String riayatiTokenUrl;

    @Value("${keystore.location}")
    private String keyStoreLocation;

    @Value("${keystore.password}")
    private char[] keyStorePassword;

    @Value("${key.alias}")
    private String keyAlias;

    @Value("${key.password}")
    private char[] keyPassword;

    @Value("${folder.path}")
    private String folderPath;

    @Value("${client.id}")
    private String clientId;

    @Value("${client.secretKey}")
    private String clientSecretKey;

    @Value("${saml.download}")
    private String downloadSaml ;

    @Value("${issuer.name}")
    private String issuerName;

    // Method to get Token
    public TokenResponseDto getRiayatiToken(String clinicianLicense) {
        MultiValueMap<String, String> params = createTokenRequestParams(clinicianLicense);
        HttpHeaders headers = createHeaders();

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<String> response = restTemplate.exchange(riayatiTokenUrl, HttpMethod.POST, request, String.class);
            return parseTokenResponse(response.getBody());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            throw new RuntimeException("Error fetching token: " + e.getMessage(), e);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error parsing token response: " + e.getMessage(), e);
        }
    }

    public SsoLauncherDto createSsoLauncherDto(String mrn, String assigningAuthority, String clinicianId) {
        SsoLauncherDto ssoLauncherDto = new SsoLauncherDto();
        ssoLauncherDto.setCLIENT_ID(clientId);
        ssoLauncherDto.setPATIENT_MRN(mrn);
        ssoLauncherDto.setPATIENT_MRN_AUTHORITY(assigningAuthority);
        ssoLauncherDto.setCLINICIAN_ID(clinicianId);
        return ssoLauncherDto;
    }

    // Generate SAML
    public String generateSamlResponse(String clinicianName, String clinicianLicense, String role) {
        try {
            SamlAttribute samlAttribute = createSamlAttribute(clinicianName, clinicianLicense, role);
            String samlResponse = samlGenerator.getSamlResponse(issuerName, "Recipient", "hsimpson", samlAttribute.getUserRole(),
                    samlAttribute, null, samlAttribute.getRole(), keyStoreLocation, keyStorePassword,
                    keyAlias, keyPassword, "Recipient");

            // To Download and Save Generated SAML
            if(downloadSaml.equalsIgnoreCase("yes")){
                saveSamlResponseToFile(samlResponse);
            }

            return Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {

            throw new RuntimeException("Error generating SAML response: " + e.getMessage(), e);
        }
    }

    // code to save SAML as a file call the method on generateSamlResponse()
    public void saveSamlResponseToFile(String samlResponse) throws IOException {
        String fileName = generateRandomFileName();
        File file = new File(folderPath, fileName);

        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(samlResponse.getBytes(StandardCharsets.UTF_8));
        }
    }

    public String validateSsoLauncherDto(String role, Model model, SsoLauncherDto ssoLauncherDto) {
        if (ssoLauncherDto.getPATIENT_MRN() == null || ssoLauncherDto.getPATIENT_MRN_AUTHORITY() == null || ssoLauncherDto.getCLINICIAN_ID() == null || role == null) {
            StringBuilder errorMessage = buildErrorMessage(role, ssoLauncherDto);
            model.addAttribute("ssoLauncherDto", ssoLauncherDto);
            model.addAttribute("errorMessage", errorMessage.toString());
            return "index";
        }
        return null;
    }

    private MultiValueMap<String, String> createTokenRequestParams(String clinicianLicense) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_secret", clientSecretKey);
        params.add("client_id", clientId);
        params.add("grant_type", "client_credentials");
        params.add("clinician_id", clinicianLicense);
        return params;
    }

    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    private TokenResponseDto parseTokenResponse(String responseBody) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(responseBody, TokenResponseDto.class);
    }

    private SamlAttribute createSamlAttribute(String clinicianName, String clinicianLicense, String role) {
        SamlAttribute samlAttribute = new SamlAttribute();
        samlAttribute.setName(clinicianName);
        String roleValue = "";
        String userRole = "";

        // Set values based on role
        if ("physician".equalsIgnoreCase(role)) {
            roleValue = "%HS_Physician";
            userRole = "Doctor";
        } else if ("nurse".equalsIgnoreCase(role)) {
            roleValue = "%HS_Nurse";
            userRole = "Nurse";
        } else if ("nurse_btg".equalsIgnoreCase(role)) {
            roleValue = "%HS_Nurse_BTG";
            userRole = "Nurse_BTG";
        } else if ("allied health".equalsIgnoreCase(role)) {
            roleValue = "%HS_AlliedHealth";
            userRole = "Allied health";
        }

        samlAttribute.setRole(roleValue);
        samlAttribute.setUserRole(userRole);
        samlAttribute.setClinicianId(clinicianLicense);
        return samlAttribute;
    }

    // Error To be displayed if missing parameters found in url in TEST
    private StringBuilder buildErrorMessage( String role, SsoLauncherDto ssoLauncherDto) {
        StringBuilder errorMessage = new StringBuilder("Missing parameters: ");
        if (ssoLauncherDto.getPATIENT_MRN() == null) errorMessage.append("MRN, ");
        if (ssoLauncherDto.getPATIENT_MRN_AUTHORITY() == null) errorMessage.append("AssigningAuthority, ");
        if (ssoLauncherDto.getCLINICIAN_ID() == null) errorMessage.append("ClinicianID, ");
        if (role == null) errorMessage.append("Role, ");
        if (errorMessage.length() > 18) { // 18 is the length of "Missing parameters: "
            errorMessage.setLength(errorMessage.length() - 2); // Remove trailing comma and space
        } else {
            errorMessage.append("No missing parameters.");
        }
        return errorMessage;
    }

    // Generate a file name for the SAML before saving
    private String generateRandomFileName() {
        return UUID.randomUUID() + ".xml";
    }
}