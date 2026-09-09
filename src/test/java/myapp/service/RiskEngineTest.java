package myapp.service;

import myapp.model.ScanSummary;
import myapp.model.SecurityFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskEngineTest {

    private final RiskEngine riskEngine = new RiskEngine();

    @Test
    void shouldReturnPerfectScoreWhenThereAreNoFindings() {

        ScanSummary summary =
                riskEngine.calculateRisk(List.of());

        assertEquals(100, summary.getSecurityScore());
        assertEquals("SECURE", summary.getRiskLevel());

        assertEquals(0, summary.getPassed());
        assertEquals(0, summary.getWarnings());
        assertEquals(0, summary.getErrors());

        assertEquals(0, summary.getHighRisk());
        assertEquals(0, summary.getMediumRisk());
        assertEquals(0, summary.getLowRisk());
    }

    @Test
    void shouldCountPassedFindingsCorrectly() {

        List<SecurityFinding> findings = List.of(
                finding("PASS", "NONE"),
                finding("PASS", "NONE"),
                finding("WARNING", "LOW")
        );

        ScanSummary summary =
                riskEngine.calculateRisk(findings);

        assertEquals(2, summary.getPassed());
        assertEquals(1, summary.getWarnings());
        assertEquals(0, summary.getErrors());

        assertEquals(0, summary.getHighRisk());
        assertEquals(0, summary.getMediumRisk());
        assertEquals(1, summary.getLowRisk());
    }

    @Test
    void shouldCalculateHighRiskCorrectly() {

        List<SecurityFinding> findings = List.of(
                finding("WARNING", "HIGH")
        );

        ScanSummary summary =
                riskEngine.calculateRisk(findings);

        assertEquals(1, summary.getHighRisk());
        assertEquals(0, summary.getMediumRisk());
        assertEquals(0, summary.getLowRisk());

        assertEquals(0, summary.getSecurityScore());
        assertEquals("HIGH", summary.getRiskLevel());
    }

    @Test
    void shouldCalculateMediumRiskCorrectly() {

        List<SecurityFinding> findings = List.of(
                finding("WARNING", "MEDIUM")
        );

        ScanSummary summary =
                riskEngine.calculateRisk(findings);

        assertEquals(0, summary.getHighRisk());
        assertEquals(1, summary.getMediumRisk());
        assertEquals(0, summary.getLowRisk());

        assertEquals(33, summary.getSecurityScore());
        assertEquals("HIGH", summary.getRiskLevel());
    }

    @Test
    void shouldCalculateLowRiskCorrectly() {

        List<SecurityFinding> findings = List.of(
                finding("WARNING", "LOW")
        );

        ScanSummary summary =
                riskEngine.calculateRisk(findings);

        assertEquals(0, summary.getHighRisk());
        assertEquals(0, summary.getMediumRisk());
        assertEquals(1, summary.getLowRisk());

        assertEquals(67, summary.getSecurityScore());
        assertEquals("MEDIUM", summary.getRiskLevel());
    }

    @Test
    void shouldCountErrorsAndApplyPenalty() {

        List<SecurityFinding> findings = List.of(
                finding("ERROR", "HIGH")
        );

        ScanSummary summary =
                riskEngine.calculateRisk(findings);

        assertEquals(0, summary.getPassed());
        assertEquals(0, summary.getWarnings());
        assertEquals(1, summary.getErrors());

        assertEquals(1, summary.getHighRisk());

        assertEquals(0, summary.getSecurityScore());
        assertEquals("HIGH", summary.getRiskLevel());
    }

    @Test
    void shouldHandleMixedFindings() {

        List<SecurityFinding> findings = List.of(
                finding("PASS", "NONE"),
                finding("WARNING", "HIGH"),
                finding("WARNING", "MEDIUM"),
                finding("WARNING", "LOW")
        );

        ScanSummary summary =
                riskEngine.calculateRisk(findings);

        assertEquals(1, summary.getPassed());
        assertEquals(3, summary.getWarnings());
        assertEquals(0, summary.getErrors());

        assertEquals(1, summary.getHighRisk());
        assertEquals(1, summary.getMediumRisk());
        assertEquals(1, summary.getLowRisk());

        assertEquals(50, summary.getSecurityScore());
        assertEquals("MEDIUM", summary.getRiskLevel());
    }

    private SecurityFinding finding(
            String status,
            String severity) {

        return new SecurityFinding(
                "TEST-001",
                "Test Security Check",
                status,
                severity,
                "Test finding",
                "Test recommendation"
        );
    }
}