package org.openmrs.module.authentication.web;

import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

public class WebUtil {

    private static AntPathMatcher matcher = new AntPathMatcher();

    static {
        matcher.setCaseSensitive(false);
        matcher.setTrimTokens(true);
    }

    /**
     * Checks if the request is for a URL that matches a configured whitelist pattern.
     * 
     * @param request the HttpServletRequest to check
     * @param whiteList the list of URL patterns to check against
     * @return true if the request is for a URL that matches a configured whitelist pattern
     */
    public static boolean isWhiteListed(HttpServletRequest request, List<String> whiteList) {
        for (String pattern : whiteList) {
            if (matchesPath(request, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks the request servlet path and requestURI against the given pattern.
     * 
     * @param request the HttpServletRequest to check
     * @param pattern the pattern to match
     * @return true if the request matches the pattern
     */
    public static boolean matchesPath(HttpServletRequest request, String pattern) {
        if (pattern.startsWith("*")) {
            pattern = "/**/" + pattern;
        }
        if (matcher.match(pattern, request.getServletPath())) {
            return true;
        }
        String patternWithContext = contextualizeUrl(request, pattern);
        return matcher.match(patternWithContext, request.getRequestURI());
    }

    /**
     * Appends the OpenMRS context path to the given URL if necessary.
     * 
     * @param request the HttpServletRequest containing the context path
     * @param url the URL to contextualize
     * @return the URL, prepended with the context path if necessary
     */
    public static String contextualizeUrl(HttpServletRequest request, String url) {
        if (url == null) {
            url = request.getContextPath();
        }
        if (!url.startsWith(request.getContextPath())) {
            url = request.getContextPath() + (url.startsWith("/") ? "" : "/") + url;
        }
        return url;
    }
}
