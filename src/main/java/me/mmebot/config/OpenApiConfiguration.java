package me.mmebot.config;

import io.micrometer.common.util.StringUtils;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import me.mmebot.common.config.ExternalServiceProperties;
import me.mmebot.common.config.JwtProperties;
import me.mmebot.common.persistence.ApiProp;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import static org.springframework.http.MediaType.APPLICATION_JSON;

@Configuration
public class OpenApiConfiguration {

    private static final String SECURITY_SCHEME_BEARER = "accessToken";
    private static final String ERROR_SCHEMA_REF = "#/components/schemas/ErrorResponse";

    @Bean
    public OpenAPI mmebotOpenApi(ApiProp apiProp,
                                 ExternalServiceProperties external,
                                 JwtProperties jwtProperties,
                                 Environment environment) {
        String basePath = normalizeBasePath(apiProp);
        List<Server> servers = buildServers(basePath, external, environment);

        SecurityScheme bearerScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("Provide the access token as an Authorization header: 'Bearer <token>'. The token is issued by sign-in and reissue flows.");

        String description = "REST API for MME Bot. All endpoints are served under '" + basePath
                + "'. Access tokens are JWTs issued by '" + jwtProperties.issuer() + "'.";

        return new OpenAPI()
                .info(new Info()
                        .title("MME Bot API")
                        .version("v1")
                        .description(description)
                        .contact(new Contact().name("MME Bot Platform")))
                .servers(servers)
                .components(new Components().addSecuritySchemes(SECURITY_SCHEME_BEARER, bearerScheme));
    }

    @Bean
    public OpenApiCustomizer mmebotOpenApiCustomizer(ApiProp apiProp) {
        String basePath = normalizeBasePath(apiProp);
        String publicAuthPrefix = basePath + "/auth";

        return openApi -> {
            if (openApi.getPaths() == null) {
                return;
            }
            openApi.getPaths().forEach((path, pathItem) -> {
                pathItem.readOperations().forEach(operation -> {
                    boolean requiresSecurity = !path.startsWith(publicAuthPrefix);
                    if (requiresSecurity) {
                        ensureSecurityRequirement(operation);
                        addResponseIfMissing(operation, "401", () -> buildErrorResponse(path, 401,
                                "Unauthorized", "Access token is missing, expired, or invalid.", "AUTH-401"));
                        addResponseIfMissing(operation, "403", () -> buildErrorResponse(path, 403,
                                "Forbidden", "The authenticated user is not allowed to access this resource.", "AUTH-403"));
                    }
                    addResponseIfMissing(operation, "400", () -> buildErrorResponse(path, 400,
                            "Bad Request", "The request payload is invalid or violates constraints.", "COMMON-400"));
                    addResponseIfMissing(operation, "404", () -> buildErrorResponse(path, 404,
                            "Not Found", "The requested resource was not found.", "COMMON-404"));
                    addResponseIfMissing(operation, "500", () -> buildErrorResponse(path, 500,
                            "Internal Server Error", "An unexpected error occurred on the server.", "COMMON-500"));
                });
            });
        };
    }

    private void ensureSecurityRequirement(Operation operation) {
        List<SecurityRequirement> security = operation.getSecurity();
        if (security == null) {
            security = new ArrayList<>();
            operation.setSecurity(security);
        }
        boolean alreadyPresent = security.stream()
                .anyMatch(requirement -> requirement.containsKey(SECURITY_SCHEME_BEARER));
        if (!alreadyPresent) {
            security.add(new SecurityRequirement().addList(SECURITY_SCHEME_BEARER));
        }
    }

    private void addResponseIfMissing(Operation operation, String statusCode, Supplier<ApiResponse> factory) {
        ApiResponses responses = operation.getResponses();
        if (responses == null) {
            responses = new ApiResponses();
            operation.setResponses(responses);
        }
        responses.computeIfAbsent(statusCode, ignored -> factory.get());
    }

    private ApiResponse buildErrorResponse(String path,
                                           int status,
                                           String error,
                                           String message,
                                           String code) {
        Map<String, Object> example = new LinkedHashMap<>();
        example.put("timestamp", "2024-01-01T00:00:00Z");
        example.put("status", status);
        example.put("error", error);
        example.put("message", message);
        example.put("code", code);
        example.put("path", path);

        Content content = new Content().addMediaType(APPLICATION_JSON.getType(), new MediaType()
                .schema(new Schema<>().$ref(ERROR_SCHEMA_REF))
                .addExamples("default", new Example().value(example)));

        return new ApiResponse()
                .description(message)
                .content(content);
    }

    private List<Server> buildServers(String basePath,
                                      ExternalServiceProperties external,
                                      Environment environment) {
        List<Server> servers = new ArrayList<>();
        String address = environment.getProperty("server.address", "localhost");
        String port = environment.getProperty("server.port", "8080");
        String localUrl = "http://" + address + ":" + port + basePath;
        servers.add(new Server().url(localUrl).description("Local development"));

        String apiGateway = external.apiGateway();
        if (StringUtils.isNotBlank(apiGateway)) {
            servers.add(new Server().url(joinUrl(apiGateway, basePath)).description("API gateway"));
        }
        return servers;
    }

    private String joinUrl(String root, String path) {
        String trimmedRoot = trimTrailingSlash(root);
        if (StringUtils.isBlank(path) || "/".equals(path)) {
            return trimmedRoot;
        }
        return trimmedRoot + path;
    }

    private String trimTrailingSlash(String value) {
        if (value.endsWith("/")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }

    private String normalizeBasePath(ApiProp apiProp) {
        String basePath = apiProp.basePath();
        if (StringUtils.isBlank(basePath)) {
            return "/api";
        }
        String normalized = basePath.trim();
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
