package com.studing.allmonster.security.services;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TreatmentError403 implements AccessDeniedHandler {
    public void handle(HttpServletRequest req, HttpServletResponse res, AccessDeniedException ex)throws IOException, ServletException {
        res.setStatus(403);
        res.setContentType("application/json");
        res.getWriter().write("Error 403! Unauthorized user");
    }
}
