// Package intel provides threat intelligence management.
package intel

import (
	"time"
)

// IndicatorType represents a type of threat indicator.
type IndicatorType string

const (
	TypeIP         IndicatorType = "ip"
	TypeDomain     IndicatorType = "domain"
	TypeURL        IndicatorType = "url"
	TypeHash       IndicatorType = "hash"
	TypeEmail      IndicatorType = "email"
	TypeFile       IndicatorType = "file"
	TypeCertificate IndicatorType = "certificate"
	TypeCIDR       IndicatorType = "cidr"
)

// ThreatIndicator represents a threat intelligence indicator.
type ThreatIndicator struct {
	ID           string
	Value        string
	Type         IndicatorType
	ThreatType   string
	Severity     string
	FirstSeen    time.Time
	LastSeen     time.Time
	Source       string
	Description  string
	Confidence   float64
	AssociatedAttacker string
	MalwareFamily string
	Tags         []string
}

// ThreatIntelSource represents a threat intelligence source.
type ThreatIntelSource struct {
	Name          string
	URL           string
	Type          string // free, paid, open_source
	Active        bool
	LastUpdated   time.Time
	Indicators    int
}

// IntelligencePlatform manages threat intelligence.
type IntelligencePlatform struct {
	indicators     map[string]*ThreatIndicator
	sources        []ThreatIntelSource
	reputations    map[string]Reputation
}

// Reputation represents reputation data.
type Reputation struct {
	IP         string
	Score      float64
	Status     string
	LastSeen   time.Time
	Activity   []Activity
}

// Activity represents threat activity.
type Activity struct {
	Type        string
	Timestamp   time.Time
	Source      string
	Description string
}

// NewIntelligencePlatform creates a new threat intel platform.
func NewIntelligencePlatform() *IntelligencePlatform {
	return &IntelligencePlatform{
		indicators: make(map[string]*ThreatIndicator),
		sources:    make([]ThreatIntelSource, 0),
		reputations: make(map[string]Reputation),
	}
}

// AddIndicator adds a threat indicator.
func (p *IntelligencePlatform) AddIndicator(indicator ThreatIndicator) {
	key := indicator.Type + ":" + indicator.Value
	p.indicators[key] = &indicator
}

// AddSource adds a threat intel source.
func (p *IntelligencePlatform) AddSource(source ThreatIntelSource) {
	p.sources = append(p.sources, source)
}

// GetIndicator retrieves an indicator.
func (p *IntelligencePlatform) GetIndicator(value string, indicatorType IndicatorType) *ThreatIndicator {
	key := string(indicatorType) + ":" + value
	return p.indicators[key]
}

// GetIndicatorsByType returns indicators by type.
func (p *IntelligencePlatform) GetIndicatorsByType(indicatorType IndicatorType) []*ThreatIndicator {
	var result []*ThreatIndicator
	for _, indicator := range p.indicators {
		if indicator.Type == indicatorType {
			result = append(result, indicator)
		}
	}
	return result
}

// SearchIndicators searches for indicators.
func (p *IntelligencePlatform) SearchIndicators(query string) []*ThreatIndicator {
	var results []*ThreatIndicator
	for _, indicator := range p.indicators {
		if contains(indicator.Value, query) || contains(indicator.Description, query) {
			results = append(results, indicator)
		}
	}
	return results
}

// contains checks if string contains substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}

// UpdateReputation updates IP reputation.
func (p *IntelligencePlatform) UpdateReputation(ip string, score float64, status string) {
	p.reputations[ip] = Reputation{
		IP:       ip,
		Score:    score,
		Status:   status,
		LastSeen: time.Now(),
		Activity: make([]Activity, 0),
	}
}

// GetReputation gets IP reputation.
func (p *IntelligencePlatform) GetReputation(ip string) Reputation {
	if rep, exists := p.reputations[ip]; exists {
		return rep
	}
	return Reputation{IP: ip, Status: "UNKNOWN"}
}

// GetSources returns all sources.
func (p *IntelligencePlatform) GetSources() []ThreatIntelSource {
	return p.sources
}

// GetIndicatorCount returns total indicator count.
func (p *IntelligencePlatform) GetIndicatorCount() int {
	return len(p.indicators)
}

// GetReputationScore calculates reputation score.
func (p *IntelligencePlatform) GetReputationScore(ip string) float64 {
	if rep, exists := p.reputations[ip]; exists {
		return rep.Score
	}
	return 0.5 // Neutral reputation
}

// IsThreat checks if indicator is malicious.
func (p *IntelligencePlatform) IsThreat(value string, indicatorType IndicatorType) bool {
	indicator := p.GetIndicator(value, indicatorType)
	if indicator == nil {
		return false
	}
	
	return indicator.Severity == "HIGH" || indicator.Severity == "CRITICAL"
}

// GetThreatActivity gets threat activity.
func (p *IntelligencePlatform) GetThreatActivity(ip string) []Activity {
	if rep, exists := p.reputations[ip]; exists {
		return rep.Activity
	}
	return make([]Activity, 0)
}

// AddActivity adds activity to reputation.
func (p *IntelligencePlatform) AddActivity(ip, activityType, source, description string) {
	if rep, exists := p.reputations[ip]; exists {
		activity := Activity{
			Type:        activityType,
			Timestamp:   time.Now(),
			Source:      source,
			Description: description,
		}
		rep.Activity = append(rep.Activity, activity)
		p.reputations[ip] = rep
	}
}

// GetAssociatedAttackers returns associated attackers.
func (p *IntelligencePlatform) GetAssociatedAttackers() map[string][]string {
	attackers := make(map[string][]string)
	
	for _, indicator := range p.indicators {
		if indicator.AssociatedAttacker != "" {
			attackers[indicator.AssociatedAttacker] = append(
				attackers[indicator.AssociatedAttacker],
				indicator.Value,
			)
		}
	}
	
	return attackers
}

// GetMalwareFamilies returns malware families.
func (p *IntelligencePlatform) GetMalwareFamilies() map[string][]string {
	families := make(map[string][]string)
	
	for _, indicator := range p.indicators {
		if indicator.MalwareFamily != "" {
			families[indicator.MalwareFamily] = append(
				families[indicator.MalwareFamily],
				indicator.Value,
			)
		}
	}
	
	return families
}

// GenerateReport generates threat intel report.
func GenerateReport(platform *IntelligencePlatform) string {
	var report string

	report += "=== Threat Intelligence Report ===\n\n"
	report += "Total Indicators: " + string(rune(platform.GetIndicatorCount()+48)) + "\n"
	report += "Intelligence Sources: " + string(rune(len(platform.GetSources())+48)) + "\n\n"

	report += "Threat Sources:\n"
	for i, source := range platform.GetSources() {
		status := "✓"
		if !source.Active {
			status = "✗"
		}
		report += "  [" + string(rune(i+49)) + "] " + status + " " + source.Name + " (" + string(rune(source.Indicators+48)) + " indicators)\n"
	}

	if len(platform.indicators) > 0 {
		report += "\nRecent Indicators:\n"
		count := 0
		for _, indicator := range platform.indicators {
			if count >= 10 {
				break
			}
			report += "  [" + string(rune(count+49)) + "] " + string(indicator.Type) + " - " + indicator.Value[:min(len(indicator.Value), 20)] + "\n"
			report += "      Severity: " + indicator.Severity + "\n"
			report += "      Threat Type: " + indicator.ThreatType + "\n\n"
			count++
		}
	}

	return report
}

// min returns minimum of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetIndicator returns indicator.
func GetIndicator(platform *IntelligencePlatform, value string, indicatorType IndicatorType) *ThreatIndicator {
	return platform.GetIndicator(value, indicatorType)
}

// GetReputation returns reputation.
func GetReputation(platform *IntelligencePlatform, ip string) Reputation {
	return platform.GetReputation(ip)
}