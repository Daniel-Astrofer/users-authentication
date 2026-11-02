package com.kerosene.content.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.content.dto.HomeSurfaceResponseDTO;
import com.kerosene.content.dto.HomeUiPublishRequestDTO;
import com.kerosene.content.model.entity.HomeUiOverrideEntity;
import com.kerosene.content.service.HomeSurfaceComposer;
import com.kerosene.content.service.HomeUiOverrideService;
import com.kerosene.content.service.HomeUiPushService;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;

/**
 * Internal ops endpoint for publishing home UI overrides and live pushes.
 * The shared internal filter authenticates the calling KFE workload.
 */
@RestController
@RequestMapping("/internal/content/home-ui")
public class HomeUiPublishController {

    /** Persists scoped, time-bounded home UI overrides. */
    private final HomeUiOverrideService overrideService;
    /** Builds a personalized current surface before snapshot pushes. */
    private final HomeSurfaceComposer surfaceComposer;
    /** Publishes snapshots, patches, and greetings to live clients. */
    private final HomeUiPushService pushService;
    /** Parses JSON payload strings supplied by internal operators. */
    private final ObjectMapper objectMapper;


    /**
     * Creates the internal publishing controller.
     *
     * @param overrideService persistence service for scoped overrides
     * @param surfaceComposer composer for user-specific full snapshots
     * @param pushService live event publisher
     * @param objectMapper JSON parser used to validate request payloads
     */
    public HomeUiPublishController(
            HomeUiOverrideService overrideService,
            HomeSurfaceComposer surfaceComposer,
            HomeUiPushService pushService,
            ObjectMapper objectMapper) {
        this.overrideService = overrideService;
        this.surfaceComposer = surfaceComposer;
        this.pushService = pushService;
        this.objectMapper = objectMapper;
    }

    /**
     * Routes an authenticated publish command to override, snapshot, patch, or greeting handling.
     *
     * @param request command discriminator and action-specific payload
     * @return success envelope with saved override or pushed event metadata
     * @throws ResponseStatusException with 401/503 for credential configuration failures and 400 for invalid requests
     */
    @PostMapping("/publish")
    public ResponseEntity<ApiResponse<Map<String, Object>>> publish(
            @RequestBody HomeUiPublishRequestDTO request) {
        require(request != null, "request is required");
        String action = request.action() == null ? "" : request.action().trim().toUpperCase(Locale.ROOT);

        return switch (action) {
            case "UPSERT_OVERRIDE" -> upsertOverride(request);
            case "PUSH_SNAPSHOT" -> pushSnapshot(request);
            case "PUSH_PATCH" -> pushPatch(request);
            case "PUSH_GREETING" -> pushGreeting(request);
            default -> throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "action must be UPSERT_OVERRIDE | PUSH_SNAPSHOT | PUSH_PATCH | PUSH_GREETING");
        };
    }

    /**
     * Validates and stores a GLOBAL, USER, or SEGMENT JSON override with optional priority and dates.
     * Active user-specific overrides also cause an immediate recomposed snapshot to be pushed.
     *
     * @param request publish command carrying override scope, payload, and optional scheduling data
     * @return saved override ID, scope, and priority
     * @throws ResponseStatusException when scope requirements, payload JSON, or timestamps are invalid
     */
    private ResponseEntity<ApiResponse<Map<String, Object>>> upsertOverride(HomeUiPublishRequestDTO request) {
        require(request.payloadJson() != null && !request.payloadJson().isBlank(), "payloadJson is required");
        String scope = request.scope() == null ? "GLOBAL" : request.scope().trim().toUpperCase(Locale.ROOT);
        if (!scope.equals("GLOBAL") && !scope.equals("USER") && !scope.equals("SEGMENT")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid scope");
        }
        if (scope.equals("USER")) {
            require(request.userId() != null, "userId required for USER scope");
        }
        if (scope.equals("SEGMENT")) {
            require(request.segmentKey() != null && !request.segmentKey().isBlank(), "segmentKey required");
        }
        try {
            JsonNode node = objectMapper.readTree(request.payloadJson());
            if (node == null || !node.isObject()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payloadJson must be a JSON object");
            }
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payloadJson is not valid JSON");
        }

        HomeUiOverrideEntity entity = new HomeUiOverrideEntity();
        entity.setScope(scope);
        entity.setUserId(request.userId());
        entity.setSegmentKey(request.segmentKey());
        entity.setPriority(request.priority() == null ? 0 : request.priority());
        entity.setActive(request.active() == null || request.active());
        entity.setStartsAt(parseInstant(request.startsAt()));
        entity.setEndsAt(parseInstant(request.endsAt()));
        entity.setPayload(request.payloadJson().trim());
        HomeUiOverrideEntity saved = overrideService.save(entity);

        if (request.userId() != null && (request.active() == null || request.active())) {
            HomeSurfaceResponseDTO surface = surfaceComposer.compose(
                    request.userId(),
                    firstNonBlank(request.balanceView(), "TOTAL"),
                    firstNonBlank(request.locale(), "pt"),
                    firstNonBlank(request.timeZone(), "UTC"));
            pushService.pushSnapshot(request.userId(), surface);
        }

        return ResponseEntity.ok(ApiResponse.success(
                "Home UI override saved.",
                Map.of("id", saved.getId(), "scope", saved.getScope(), "priority", saved.getPriority())));
    }

    /**
     * Composes and pushes the current personalized snapshot using request values or stable defaults.
     *
     * @param request command containing the target user and optional view/locale/time zone
     * @return target user and composed snapshot version
     * @throws ResponseStatusException when userId is absent
     */
    private ResponseEntity<ApiResponse<Map<String, Object>>> pushSnapshot(HomeUiPublishRequestDTO request) {
        require(request.userId() != null, "userId is required");
        HomeSurfaceResponseDTO surface = surfaceComposer.compose(
                request.userId(),
                firstNonBlank(request.balanceView(), "TOTAL"),
                firstNonBlank(request.locale(), "pt"),
                firstNonBlank(request.timeZone(), "UTC"));
        pushService.pushSnapshot(request.userId(), surface);
        return ResponseEntity.ok(ApiResponse.success(
                "Home UI snapshot pushed.",
                Map.of("userId", request.userId(), "version", surface.version())));
    }

    /**
     * Parses and pushes a raw home UI patch for the requested user with a current ISO instant marker.
     *
     * @param request command containing a user ID and JSON patch
     * @return success metadata for the target user
     * @throws ResponseStatusException when required values are absent or payload JSON is invalid
     */
    private ResponseEntity<ApiResponse<Map<String, Object>>> pushPatch(HomeUiPublishRequestDTO request) {
        require(request.userId() != null, "userId is required");
        require(request.payloadJson() != null && !request.payloadJson().isBlank(), "payloadJson is required");
        try {
            JsonNode patch = objectMapper.readTree(request.payloadJson());
            pushService.pushPatch(request.userId(), patch, Instant.now().toString());
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payloadJson is not valid JSON");
        }
        return ResponseEntity.ok(ApiResponse.success(
                "Home UI patch pushed.",
                Map.of("userId", request.userId())));
    }

    /**
     * Parses and pushes a greeting payload for the requested user with a current ISO instant marker.
     *
     * @param request command containing a user ID and JSON greeting
     * @return success metadata for the target user
     * @throws ResponseStatusException when required values are absent or payload JSON is invalid
     */
    private ResponseEntity<ApiResponse<Map<String, Object>>> pushGreeting(HomeUiPublishRequestDTO request) {
        require(request.userId() != null, "userId is required");
        require(request.payloadJson() != null && !request.payloadJson().isBlank(), "payloadJson is required");
        try {
            JsonNode greeting = objectMapper.readTree(request.payloadJson());
            pushService.pushGreeting(request.userId(), greeting, Instant.now().toString());
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payloadJson is not valid JSON");
        }
        return ResponseEntity.ok(ApiResponse.success(
                "Home UI greeting pushed.",
                Map.of("userId", request.userId())));
    }

    /**
     * Parses a nullable optional ISO-8601 instant used by an override's active window.
     *
     * @param raw timestamp text, null/blank when the corresponding bound is open-ended
     * @return parsed instant or null for an absent bound
     * @throws ResponseStatusException when a nonblank value is not a valid ISO instant
     */
    private Instant parseInstant(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(raw.trim());
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid instant: " + raw);
        }
    }

    /**
     * Returns a trimmed nonblank request value or its supplied default.
     *
     * @param value optional request value
     * @param fallback value used when input is null or blank
     * @return normalized value or fallback
     */
    private static String firstNonBlank(String value, String fallback) {
        if (value != null && !value.isBlank()) {
            return value.trim();
        }
        return fallback;
    }

    /**
     * Converts failed request preconditions to a 400 response.
     *
     * @param condition predicate that must hold
     * @param message client-facing validation message
     * @throws ResponseStatusException when condition is false
     */
    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
        }
    }
}
