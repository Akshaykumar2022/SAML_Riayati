package com.pappyjoe.saml_riayati.models.dtos;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class TokenResponseDto {
    private String token_type;
    private String access_token;
    private int expires_in;

}
