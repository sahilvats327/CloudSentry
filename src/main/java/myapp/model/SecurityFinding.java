
package myapp.model;

public class SecurityFinding {

    private final String ruleId;
    private final String check;
    private final String status;
    private final String severity;
    private final String message;
    private final String recommendation;

    public SecurityFinding(
            String ruleId,
            String check,
            String status,
            String severity,
            String message,
            String recommendation) {

        this.ruleId = ruleId;
        this.check = check;
        this.status = status;
        this.severity = severity;
        this.message = message;
        this.recommendation = recommendation;
    } 
    public SecurityFinding(
        String check,
        String status,
        String severity,
        String message,
        String recommendation) {

    this.ruleId = "UNASSIGNED";
    this.check = check;
    this.status = status;
    this.severity = severity;
    this.message = message;
    this.recommendation = recommendation;
}

    public String getId() {
    return ruleId;
}
    public String getRuleId() {
        return ruleId;
    }

    public String getCheck() {
        return check;
    }

    public String getStatus() {
        return status;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMessage() {
        return message;
    }

    public String getRecommendation() {
        return recommendation;
    }
    
}

