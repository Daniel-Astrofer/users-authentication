package com.kerosene.admin.cell;

import com.kerosene.platform.security.AdminRoles;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/operations/cell")
@PreAuthorize(AdminRoles.HAS_ADMIN_OR_OPERATOR)
public class CellOperationsController {
    private final CellOperationsService service;
    public CellOperationsController(CellOperationsService service) { this.service = service; }
    @GetMapping public Map<String, Object> snapshot() { return service.snapshot(); }
    @GetMapping("/releases") public Map<String, Object> releases() {
        var snapshot = service.snapshot();
        var result = metadata(snapshot);
        for (String key : List.of("currentRelease", "targetRelease", "coreRuntime")) result.put(key, snapshot.get(key));
        return result;
    }
    @GetMapping("/quorum") public Map<String, Object> quorum() { return section("quorum"); }
    @GetMapping("/blockers") public Map<String, Object> blockers() { return section("blockers"); }
    @GetMapping("/backups") public Map<String, Object> backups() { return section("backups"); }
    @GetMapping("/updates") public Map<String, Object> updates() throws Exception {
        var result = section("update"); result.put("plans", service.plans()); return result;
    }
    @GetMapping("/updates/plans") public List<Map<String, Object>> plans() throws Exception { return service.plans(); }
    @GetMapping("/updates/plans/{id}") public Map<String, Object> plan(@PathVariable String id) throws Exception { return service.plan(id); }
    @PostMapping("/updates/plans") public Map<String, Object> plan(@RequestBody CellOperationsService.PlanRequest body,
            Principal principal, HttpServletRequest request) throws Exception {
        return service.plan(body, principal.getName(), (String) request.getAttribute(CellOperationsAudit.REQUEST_ID));
    }
    /** Preserves intentional HTTP rejection codes in the presence of global exception advice. */
    @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
    public org.springframework.http.ResponseEntity<Map<String, String>> rejected(
            org.springframework.web.server.ResponseStatusException failure) {
        return org.springframework.http.ResponseEntity.status(failure.getStatusCode())
                .header("Cache-Control", "no-store").body(Map.of("code", "cell_request_rejected"));
    }
    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public org.springframework.http.ResponseEntity<Map<String, String>> denied() {
        return org.springframework.http.ResponseEntity.status(403).header("Cache-Control", "no-store")
                .body(Map.of("code", "cell_access_denied"));
    }
    @ExceptionHandler({java.io.IOException.class, java.io.UncheckedIOException.class})
    public org.springframework.http.ResponseEntity<Map<String, String>> storageUnavailable() {
        return org.springframework.http.ResponseEntity.status(503).header("Cache-Control", "no-store")
                .body(Map.of("code", "cell_plan_storage_unavailable"));
    }
    private Map<String, Object> section(String field) {
        var snapshot = service.snapshot();
        var result = metadata(snapshot); result.put(field, snapshot.get(field));
        return result;
    }
    private Map<String, Object> metadata(Map<String, Object> snapshot) {
        var result = new java.util.LinkedHashMap<String, Object>();
        for (String key : List.of("schema", "checkedAt", "cellId", "networkId", "verification", "evidenceDigest", "issuedAt", "expiresAt",
                "fresh", "ready", "blockers", "kfeMaintenance", "maximumAgeSeconds")) result.put(key, snapshot.get(key));
        return result;
    }
}
