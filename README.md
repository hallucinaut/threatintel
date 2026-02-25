# threatintel - Threat Intelligence Integration Platform

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Integrate threat intelligence with security events for enhanced detection and response.**

Correlate security events with threat intelligence to identify attacks and attribute threats.

## 🚀 Features

- **Threat Intelligence Management**: Store and manage threat indicators
- **Event Correlation**: Correlate security events with threat intel
- **IP Reputation**: Check IP addresses against threat feeds
- **Indicator Checking**: Validate indicators against threat intelligence
- **Attack Attribution**: Identify associated threat actors
- **Malware Tracking**: Track malware families and campaigns

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/threatintel.git
cd threatintel
go build -o threatintel ./cmd/threatintel
sudo mv threatintel /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/threatintel/cmd/threatintel@latest
```

## 🎯 Usage

### Add Indicator

```bash
# Add threat indicator
threatintel add ip 192.168.1.100
threatintel add domain malicious.com
threatintel add hash abc123def456
```

### Check Indicator

```bash
# Check if indicator is malicious
threatintel check 192.168.1.100
```

### Check Reputation

```bash
# Check IP reputation
threatintel reputation 10.0.0.1
```

### Correlate Events

```bash
# Correlate events with threat intel
threatintel correlate
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/threatintel/pkg/intel"
    "github.com/hallucinaut/threatintel/pkg/correlate"
)

func main() {
    // Create threat intel platform
    platform := intel.NewIntelligencePlatform()
    
    // Add indicator
    indicator := intel.ThreatIndicator{
        ID:       "ind-001",
        Value:    "192.168.1.100",
        Type:     intel.TypeIP,
        ThreatType: "malware_c2",
        Severity: "HIGH",
        AssociatedAttacker: "APT29",
    }
    
    platform.AddIndicator(indicator)
    
    // Check if malicious
    isThreat := platform.IsThreat("192.168.1.100", intel.TypeIP)
    fmt.Printf("Is Threat: %v\n", isThreat)
    
    // Check reputation
    platform.UpdateReputation("10.0.0.1", 0.2, "malicious")
    rep := platform.GetReputation("10.0.0.1")
    fmt.Printf("Reputation: %s\n", rep.Status)
    
    // Correlate events
    correlator := correlate.NewCorrelator()
    events := []correlate.Event{
        {
            ID: "evt-001",
            Data: map[string]interface{}{"ip": "192.168.1.100", "severity": "HIGH"},
        },
    }
    
    correlations := correlator.Correlate(events)
    fmt.Printf("Correlations: %d\n", len(correlations))
}
```

## 🔍 Indicator Types

| Type | Example | Use Case |
|------|---------|----------|
| IP | 192.168.1.100 | Network threat detection |
| Domain | malicious.com | DNS-based threats |
| URL | http://evil.com | Web-based attacks |
| Hash | abc123... | File malware detection |
| Email | spam@evil.com | Phishing detection |
| File | malware.exe | File-based threats |
| Certificate | cert123 | Certificate-based threats |
| CIDR | 10.0.0.0/24 | Network ranges |

## 🛡️ Threat Intelligence Features

### IP Reputation

- Score calculation (0-100%)
- Status tracking (malicious, suspicious, clean)
- Activity history
- Source attribution

### Indicator Checking

- Malicious IP detection
- Malicious domain check
- File hash validation
- URL reputation
- Email reputation

### Event Correlation

- IP reputation correlation
- Domain intelligence matching
- Hash comparison
- Attack pattern detection
- Threat actor attribution

### Threat Actor Tracking

- Associated attacker identification
- Campaign tracking
- TTP mapping
- Attribution analysis

## 📊 Correlation Rules

### Pre-configured Rules

1. **Malicious IP Activity** - Correlate with known bad IPs
2. **Suspicious Domain** - Check domain reputation
3. **Malware Hash** - Match against malware databases
4. **Phishing Email** - Detect phishing attempts
5. **C2 Communication** - Identify command and control

### Custom Rules

Create custom correlation rules:
- Define conditions based on event fields
- Set thresholds for triggering
- Specify actions and notifications
- Configure priorities

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/correlate -run TestCorrelateEvents
```

## 📋 Example Output

```
Checking indicator: 192.168.1.100

⚠️  Indicator 192.168.1.100 is MALICIOUS
Threat Type: malware_c2
Severity: HIGH
Associated Attacker: APT29
Malware Family: Cobalt Strike

=== Threat Intelligence Correlation Report ===

Total Correlations: 1

Correlated Events:
[1] HIGH - Risk Score: 75%
    Attack Pattern: Malicious IP Activity
    Indicators: 2 found
    Recommendation: Investigate within 24 hours
```

## 🔒 Security Use Cases

- **Threat Hunting**: Correlate events with threat intel
- **Incident Response**: Identify attack sources
- **Security Monitoring**: Real-time threat detection
- **Threat Attribution**: Identify threat actors
- **Security Operations**: Enhance SOC capabilities

## 🛡️ Best Practices

1. **Integrate multiple threat intel feeds**
2. **Regularly update indicators**
3. **Correlate with internal logs**
4. **Automate response actions**
5. **Maintain indicator history**
6. **Share threat intelligence**
7. **Monitor indicator expiration**

## 🏗️ Architecture

```
threatintel/
├── cmd/
│   └── threatintel/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── intel/
│   │   ├── intel.go        # Threat intel management
│   │   └── intel_test.go   # Unit tests
│   └── correlate/
│       ├── correlate.go    # Event correlation
│       └── correlate_test.go # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Threat intelligence community
- Security researchers
- Open source threat feeds

## 🔗 Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Open Threat Exchange](https://otx.alienvault.com/)
- [MISP](https://misp-project.org/)
- [Threat Intelligence Platforms](https://www.mandiant.com/resources/threat-intelligence-platforms)

---

**Built with GPU by [hallucinaut](https://github.com/hallucinaut)**