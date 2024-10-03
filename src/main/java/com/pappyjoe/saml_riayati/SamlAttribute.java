package com.pappyjoe.saml_riayati;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SamlAttribute {

    private String name;
    private String clinicianId;
    private String role;
    private String userRole;


}
