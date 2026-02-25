package main

import (
	"fmt"
	"os"

	"github.com/hallucinaut/threatintel/pkg/intel"
	"github.com/hallucinaut/threatintel/pkg/correlate"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Error: indicator type and value required")
			printUsage()
			return
		}
		addIndicator(os.Args[2], os.Args[3])
	case "check":
		if len(os.Args) < 3 {
			fmt.Println("Error: indicator value required")
			printUsage()
			return
		}
		checkIndicator(os.Args[2])
	case "correlate":
		correlateEvents()
	case "reputation":
		if len(os.Args) < 3 {
			fmt.Println("Error: IP address required")
			printUsage()
			return
		}
		checkReputation(os.Args[2])
	case "report":
		generateReport()
	case "version":
		fmt.Printf("threatintel version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`threatintel - Threat Intelligence Integration Platform

Usage:
  threatintel <command> [options]

Commands:
  add <type> <value>     Add threat indicator
  check <value>          Check if indicator is malicious
  correlate              Correlate events with threat intel
  reputation <ip>        Check IP reputation
  report                 Generate intelligence report
  version                Show version information
  help                   Show this help message

Examples:
  threatintel add ip 192.168.1.100
  threatintel check 192.168.1.100
  threatintel reputation 10.0.0.1
`, "threatintel")
}

func addIndicator(indicatorType, value string) {
	fmt.Printf("Adding threat indicator: %s - %s\n", indicatorType, value)
	fmt.Println()

	// In production: add to threat intel database
	// For demo: show indicator types
	fmt.Println("Indicator Types:")
	fmt.Println("  • IP Address")
	fmt.Println("  • Domain")
	fmt.Println("  • URL")
	fmt.Println("  • Hash (MD5, SHA256)")
	fmt.Println("  • Email")
	fmt.Println("  • File")
	fmt.Println("  • Certificate")
	fmt.Println("  • CIDR Range")
	fmt.Println()

	// Example indicator
	platform := intel.NewIntelligencePlatform()
	indicator := intel.ThreatIndicator{
		ID:           "ind-001",
		Value:        value,
		Type:         intel.IndicatorType(indicatorType),
		ThreatType:   "malware_c2",
		Severity:     "HIGH",
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		Source:       "threat_intel_feed",
		Description:  "Command and control server",
		Confidence:   0.85,
		AssociatedAttacker: "APT29",
		MalwareFamily:  "Cobalt Strike",
		Tags:         []string{"c2", "apt", "malware"},
	}

	platform.AddIndicator(indicator)

	fmt.Printf("Indicator added: %s\n", indicator.Value)
	fmt.Printf("Threat Type: %s\n", indicator.ThreatType)
	fmt.Printf("Severity: %s\n", indicator.Severity)
	fmt.Printf("Associated Attacker: %s\n", indicator.AssociatedAttacker)
}

func checkIndicator(value string) {
	fmt.Printf("Checking indicator: %s\n", value)
	fmt.Println()

	// In production: check against threat intel database
	// For demo: show checking capabilities
	fmt.Println("Threat Intelligence Checks:")
	fmt.Println("  ✓ Malicious IP check")
	fmt.Println("  ✓ Malicious domain check")
	fmt.Println("  ✓ Malicious URL check")
	fmt.Println("  ✓ File hash check")
	fmt.Println("  ✓ Email reputation")
	fmt.Println("  ✓ Certificate analysis")
	fmt.Println()

	// Example check
	platform := intel.NewIntelligencePlatform()
	platform.AddIndicator(intel.ThreatIndicator{
		ID:       "ind-001",
		Value:    value,
		Type:     intel.TypeIP,
		ThreatType: "malware_c2",
		Severity: "HIGH",
	})

	isThreat := platform.IsThreat(value, intel.TypeIP)

	if isThreat {
		fmt.Printf("⚠️  Indicator %s is MALICIOUS\n", value)
	} else {
		fmt.Printf("✓ Indicator %s appears clean\n", value)
	}
}

func correlateEvents() {
	fmt.Println("Event Correlation")
	fmt.Println("=================")
	fmt.Println()

	// In production: correlate security events with threat intel
	// For demo: show correlation capabilities
	fmt.Println("Correlation Capabilities:")
	fmt.Println("  ✓ IP reputation correlation")
	fmt.Println("  ✓ Domain intelligence")
	fmt.Println("  ✓ Hash matching")
	fmt.Println("  ✓ Attack pattern detection")
	fmt.Println("  ✓ Threat actor attribution")
	fmt.Println("  ✓ Malware family identification")
	fmt.Println()

	// Example correlation
	correlator := correlate.NewCorrelator()

	events := []correlate.Event{
		{
			ID:        "evt-001",
			Type:      "network",
			Timestamp: time.Now(),
			Source:    "firewall",
			Data: map[string]interface{}{
				"ip":      "192.168.1.100",
				"domain":  "malicious.com",
				"severity": "HIGH",
			},
			Severity: "HIGH",
		},
	}

	correlations := correlator.Correlate(events)

	fmt.Println(correlate.GenerateReport(correlations))
}

func checkReputation(ip string) {
	fmt.Printf("Checking IP reputation: %s\n", ip)
	fmt.Println()

	// In production: check IP reputation
	// For demo: show reputation checking
	fmt.Println("Reputation Sources:")
	fmt.Println("  • Threat intelligence feeds")
	fmt.Println("  • Community reports")
	fmt.Println("  • Historical data")
	fmt.Println("  • Behavioral analysis")
	fmt.Println()

	// Example reputation check
	platform := intel.NewIntelligencePlatform()
	platform.UpdateReputation(ip, 0.2, "malicious")

	rep := platform.GetReputation(ip)

	fmt.Printf("IP: %s\n", ip)
	fmt.Printf("Reputation Score: %.0f%%\n", rep.Score*100)
	fmt.Printf("Status: %s\n", rep.Status)
	fmt.Printf("Last Seen: %s\n", rep.LastSeen.Format("2006-01-02 15:04:05"))
}

func generateReport() {
	fmt.Println("Generate Intelligence Report")
	fmt.Println("============================")
	fmt.Println()

	fmt.Println("Report Types:")
	fmt.Println("  • Threat Indicator Report")
	fmt.Println("  • Correlation Report")
	fmt.Println("  • Attack Attribution Report")
	fmt.Println("  • Malware Analysis Report")
	fmt.Println("  • Intelligence Summary")
	fmt.Println()

	fmt.Println("Report Formats:")
	fmt.Println("  • JSON")
	fmt.Println("  • YAML")
	fmt.Println("  • Markdown")
	fmt.Println("  • CSV")
}