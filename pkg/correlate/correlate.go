// Package correlate provides threat intelligence correlation.
package correlate

import (
	"time"
)

// CorrelationRule represents a correlation rule.
type CorrelationRule struct {
	ID          string
	Name        string
	Description string
	Conditions  []Condition
	Actions     []Action
	Priority    int
	Enabled     bool
}

// Condition represents a correlation condition.
type Condition struct {
	Field      string
	Operator   string
	Value      interface{}
	ThreatType string
}

// Action represents a correlation action.
type Action struct {
	Type       string
	Target     string
	Payload    interface{}
	Notification string
}

// CorrelationEvent represents a correlated event.
type CorrelationEvent struct {
	ID           string
	Timestamp    time.Time
	Events       []Event
	ThreatLevel  string
	RiskScore    float64
	Indicators   []string
	AttackPattern string
	Recommendation string
}

// Event represents a security event.
type Event struct {
	ID          string
	Type        string
	Timestamp   time.Time
	Source      string
	Data        map[string]interface{}
	Severity    string
}

// Correlator correlates events with threat intelligence.
type Correlator struct {
	rules        []CorrelationRule
	intelData    map[string]string
}

// NewCorrelator creates a new event correlator.
func NewCorrelator() *Correlator {
	return &Correlator{
		rules: make([]CorrelationRule, 0),
		intelData: make(map[string]string),
	}
}

// AddRule adds a correlation rule.
func (c *Correlator) AddRule(rule CorrelationRule) {
	c.rules = append(c.rules, rule)
}

// Correlate correlates events with threat intelligence.
func (c *Correlator) Correlate(events []Event) []*CorrelationEvent {
	var correlations []*CorrelationEvent

	for _, event := range events {
		correlation := c.CorrelateEvent(event)
		if correlation != nil {
			correlations = append(correlations, correlation)
		}
	}

	return correlations
}

// correlateEvent correlates a single event.
func (c *Correlator) CorrelateEvent(event Event) *CorrelationEvent {
	for _, rule := range c.rules {
		if !rule.Enabled {
			continue
		}

		if c.matchesConditions(rule.Conditions, event) {
			return c.createCorrelation(rule, event)
		}
	}

	return nil
}

// matchesConditions checks if event matches rule conditions.
func (c *Correlator) matchesConditions(conditions []Condition, event Event) bool {
	for _, condition := range conditions {
		value := event.Data[condition.Field]
		if !evaluateCondition(value, condition.Operator, condition.Value) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a condition.
func evaluateCondition(value interface{}, operator string, expected interface{}) bool {
	switch v := value.(type) {
	case string:
		switch operator {
		case "==":
			return v == expected.(string)
		case "!=":
			return v != expected.(string)
		case "contains":
			return containsString(v, expected.(string))
		case "startswith":
			return len(v) >= len(expected.(string)) && v[:len(expected.(string))] == expected.(string)
		}
	case int:
		switch operator {
		case "==":
			return v == expected.(int)
		case ">":
			return v > expected.(int)
		case "<":
			return v < expected.(int)
		}
	}

	return false
}

// containsString checks if string contains substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && (s[0:len(substr)] == substr || containsString(s[1:], substr))))
}

// createCorrelation creates a correlation event.
func (c *Correlator) createCorrelation(rule CorrelationRule, event Event) *CorrelationEvent {
	threatLevel := calculateThreatLevel(event)
	riskScore := calculateRiskScore(event)

	return &CorrelationEvent{
		ID:           "corr-" + time.Now().Format("20060102150405"),
		Timestamp:    time.Now(),
		Events:       []Event{event},
		ThreatLevel:  threatLevel,
		RiskScore:    riskScore,
		Indicators:   extractIndicators(event),
		AttackPattern: rule.Name,
		Recommendation: getRecommendation(threatLevel),
	}
}

// calculateThreatLevel calculates threat level.
func calculateThreatLevel(event Event) string {
	switch event.Severity {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// calculateRiskScore calculates risk score.
func calculateRiskScore(event Event) float64 {
	severityScores := map[string]float64{
		"CRITICAL": 1.0,
		"HIGH":     0.75,
		"MEDIUM":   0.5,
		"LOW":      0.25,
	}

	if score, exists := severityScores[event.Severity]; exists {
		return score * 100.0
	}

	return 50.0
}

// extractIndicators extracts indicators from event.
func extractIndicators(event Event) []string {
	var indicators []string

	for key, value := range event.Data {
		if key == "ip" || key == "domain" || key == "hash" || key == "url" {
			indicators = append(indicators, value.(string))
		}
	}

	return indicators
}

// getRecommendation gets recommendation based on threat level.
func getRecommendation(threatLevel string) string {
	recommendations := map[string]string{
		"CRITICAL": "Immediate investigation and response required",
		"HIGH":     "Investigate within 24 hours",
		"MEDIUM":   "Review and monitor",
		"LOW":      "Log and monitor",
		"UNKNOWN":  "Investigate to determine severity",
	}

	if rec, exists := recommendations[threatLevel]; exists {
		return rec
	}

	return "Review and investigate"
}

// GetCorrelations returns all correlations.
func (c *Correlator) GetCorrelations() []*CorrelationEvent {
	return c.Correlate(make([]Event, 0))
}

// GenerateReport generates correlation report.
func GenerateReport(correlations []*CorrelationEvent) string {
	var report string

	report += "=== Threat Intelligence Correlation Report ===\n\n"
	report += "Total Correlations: " + string(rune(len(correlations)+48)) + "\n\n"

	if len(correlations) > 0 {
		report += "Correlated Events:\n"
		for i, corr := range correlations {
			report += "[" + string(rune(i+49)) + "] " + corr.ThreatLevel + " - Risk Score: " + string(rune(int(corr.RiskScore)+48)) + "%\n"
			report += "    Attack Pattern: " + corr.AttackPattern + "\n"
			report += "    Indicators: " + string(rune(len(corr.Indicators)+48)) + " found\n"
			report += "    Recommendation: " + corr.Recommendation + "\n\n"
		}
	} else {
		report += "✓ No correlations detected\n"
	}

	return report
}

// AddIntelData adds intelligence data.
func (c *Correlator) AddIntelData(key, value string) {
	c.intelData[key] = value
}

// GetIntelData gets intelligence data.
func (c *Correlator) GetIntelData(key string) string {
	return c.intelData[key]
}

// CorrelateWithIntel correlates events with threat intel.
func CorrelateWithIntel(events []Event, intelData map[string]string) []*CorrelationEvent {
	correlator := NewCorrelator()

	// Add threat intel data
	for key, value := range intelData {
		correlator.AddIntelData(key, value)
	}

	// Add correlation rules
	correlator.AddRule(CorrelationRule{
		ID:          "rule-001",
		Name:        "Malicious IP Activity",
		Description: "Correlate events with malicious IPs",
		Conditions: []Condition{
			{Field: "ip", Operator: "==", Value: "malicious_ip", ThreatType: "ip"},
		},
		Actions: []Action{
			{Type: "alert", Target: "siem", Notification: "Malicious IP detected"},
		},
		Priority: 1,
		Enabled:  true,
	})

	return correlator.Correlate(events)
}

// GetCorrelationEvent returns correlation event.
func GetCorrelationEvent(corr *CorrelationEvent) *CorrelationEvent {
	return corr
}