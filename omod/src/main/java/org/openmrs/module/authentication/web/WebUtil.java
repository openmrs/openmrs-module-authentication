package org.openmrs.module.authentication.web;

import org.apache.commons.collections.map.CaseInsensitiveMap;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

public class WebUtil {

    private static final AntPathMatcher matcher = new AntPathMatcher();

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
     * Prepends the OpenMRS context path to the given URL if necessary.
     * 
     * @param request the HttpServletRequest containing the context path
     * @param url the URL to contextualize
     * @return the URL, prepended with the context path if necessary
     */
    public static String contextualizeUrl(HttpServletRequest request, String url) {
        return contextualizeUrl(request.getContextPath(), url);
    }

    /**
     * Prepends the OpenMRS context path to the given URL if necessary.
     *
     * @param contextPath the context path to use
     * @param url the URL to contextualize
     * @return the URL, prepended with the context path if necessary
     */
    public static String contextualizeUrl(String contextPath, String url) {
        if (url == null) {
            url = contextPath;
        }

        if (!url.startsWith(contextPath)) {
            url = contextPath + (url.startsWith("/") ? "" : "/") + url;
        }

        return url;
    }

    public static String contextualizeAbsoluteUrl(HttpServletRequest request, String url) {
        String scheme, host, port;

        if (StringUtils.isNotBlank(request.getHeader("Forwarded"))) {
            // Forwarded: by=<identifier>;for=<identifier>;host=<host>;proto=<http|https>
            String forwarded = request.getHeader("Forwarded");

            @SuppressWarnings("unchecked")
            Map<String, String> forwardedHeader = new CaseInsensitiveMap();
            if (StringUtils.isNotBlank(forwarded)) {
                for (String segment : forwarded.split(";")) {
                    String[] pairs = segment.split("=");
                    if (pairs.length > 0) {
                        if (!pairs[0].equalsIgnoreCase("for")) {
                            forwardedHeader.put(pairs[0], pairs[1]);
                        } else {
                            String firstFor = pairs[1].split(",")[0];
                            forwardedHeader.put(pairs[0], firstFor);
                        }
                    }
                }
            }

            scheme = forwardedHeader.get("proto");
            if (StringUtils.isBlank(scheme)) {
                scheme = request.getScheme();
            }

            host = forwardedHeader.get("host");
            if (StringUtils.isBlank(host)) {
                host = request.getServerName();
            }

            int serverPort = request.getServerPort();
            if ("http".equalsIgnoreCase(request.getScheme())) {
                port = serverPort == 80 ? "" : ":" + serverPort;
            } else if ("https".equalsIgnoreCase(request.getScheme())) {
                port = serverPort == 443 ? "" : ":" + serverPort;
            } else {
                port = ":" + serverPort;
            }
        } else if (StringUtils.isNotBlank("X-ForwardedFor")) {
            scheme = request.getScheme();
            host = request.getServerName();
            int serverPort = request.getServerPort();
            if ("http".equalsIgnoreCase(request.getScheme())) {
                port = serverPort == 80 ? "" : ":" + serverPort;
            } else if ("https".equalsIgnoreCase(request.getScheme())) {
                port = serverPort == 443 ? "" : ":" + serverPort;
            } else {
                port = ":" + serverPort;
            }
        } else {
            if (StringUtils.isNotBlank(request.getHeader("X-Forwarded-Proto"))) {
                scheme = request.getHeader("X-Forwarded-Proto");
            } else {
                scheme = request.getScheme();
            }

            if (StringUtils.isNotBlank(request.getHeader("X-Forwarded-Host"))) {
                host = request.getHeader("X-Forwarded-Host");
            } else {
                host = request.getServerName();
            }

            int serverPort = request.getServerPort();
            if (StringUtils.isNotBlank(request.getHeader("X-Forwarded-Port"))) {
                port = ":" + request.getHeader("X-Forwarded-Port");
                if (scheme.equalsIgnoreCase("http") && port.equals(":80")) {
                    port = "";
                } else if (scheme.equalsIgnoreCase("https") && port.equals(":443")) {
                    port = "";
                }
            } else if ("http".equalsIgnoreCase(request.getScheme())) {
                port = serverPort == 80 ? "" : ":" + serverPort;
            } else if ("https".equalsIgnoreCase(request.getScheme())) {
                port = serverPort == 443 ? "" : ":" + serverPort;
            } else {
                port = ":" + serverPort;
            }
        }



        return scheme + "://" + host + port + StringUtils.defaultString(request.getContextPath()) + (url == null ? "" : (url.startsWith("/") ? "" : "/") + url);
    }
}
