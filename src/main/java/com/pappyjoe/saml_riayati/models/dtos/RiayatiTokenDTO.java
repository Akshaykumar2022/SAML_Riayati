package com.pappyjoe.saml_riayati.models.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class RiayatiTokenDTO {

    private String grant_type;
    private String client_id;
    private String clinician_id;
    private String client_secret;





}
