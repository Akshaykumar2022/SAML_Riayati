package com.pappyjoe.saml_riayati.controller;

import com.pappyjoe.saml_riayati.models.dtos.SsoLauncherDto;
import com.pappyjoe.saml_riayati.models.dtos.TokenResponseDto;
import com.pappyjoe.saml_riayati.services.RiayatiService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@CrossOrigin(origins = "*")
public class RiayatiController {

    @Value("${client.id}")
    private String clientId;

    @Value("${riayati.sso.url}")
    private String ssoUrl;

    @Value("${riayati.deployment}")
    private String deploymentMode;

    private final RiayatiService riayatiService;

    public RiayatiController(RiayatiService riayatiService) {
        this.riayatiService = riayatiService;
    }

    @GetMapping("/submitSSO")
    public String handleSsoRequest(
            @RequestParam(value = "MRN", required = false) String mrn,
            @RequestParam(value = "AssigningAuthority", required = false) String assigningAuthority,
            @RequestParam(value = "ClinicianID", required = false) String clinicianId,
            @RequestParam(value = "Role", required = false) String role,
            @RequestParam(value = "Name", required = false) String name,
            Model model) {

        SsoLauncherDto ssoLauncherDto = riayatiService.createSsoLauncherDto(mrn, assigningAuthority, clinicianId);
        if(deploymentMode.equalsIgnoreCase("test")){
            String errorPage = riayatiService.validateSsoLauncherDto( role, model, ssoLauncherDto);

            if (errorPage != null) {
                return errorPage;
            }
        }

        model.addAttribute("ssoUrl", ssoUrl);
        try {
            ssoLauncherDto.setSAMLResponse(riayatiService.generateSamlResponse(name, clinicianId, role));
            TokenResponseDto tokenResponse = riayatiService.getRiayatiToken(clinicianId);
            ssoLauncherDto.setTOKEN(tokenResponse.getAccess_token());
            model.addAttribute("ssoLauncherDto", ssoLauncherDto);
            return "live".equalsIgnoreCase(deploymentMode) ? "redirectSSO" : "index";
        } catch (RuntimeException e) {
            model.addAttribute("errorMessage", e.getMessage());
            model.addAttribute("ssoLauncherDto", ssoLauncherDto);
            return "live".equalsIgnoreCase(deploymentMode) ? "errorPage" : "index";

        }

    }
}
