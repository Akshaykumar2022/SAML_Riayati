package com.pappyjoe.saml_riayati.models.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SsoLauncherDto {
    private String PATIENT_MRN;
    private String CLIENT_ID;
    private String TOKEN;
    private String CLINICIAN_ID;
    private String PATIENT_MRN_AUTHORITY;
    private String SAMLResponse;

}
