#include "rules.h"
#include <fstream>
#include <sstream>
#include <vector>

bool RuleEngine::load_rules(const std::string& file_path) {
    std::ifstream infile(file_path);
    if (!infile.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::vector<std::string> parts;
        std::string token;

        while (iss >> token) {
            parts.push_back(token);
        }

        // Expected format:
        // ACTION FINGERPRINT REASON RISK_LEVEL
        if (parts.size() >= 4) {
            RuleDecision decision;
            decision.action = parts[0];
            std::string fingerprint = parts[1];
            decision.reason = parts[2];
            decision.risk_level = parts[3];

            rules_[fingerprint] = decision;
        }
        // Backward compatibility:
        // ACTION FINGERPRINT
        else if (parts.size() >= 2) {
            RuleDecision decision;
            decision.action = parts[0];
            std::string fingerprint = parts[1];

            if (decision.action == "BLOCK") {
                decision.reason = "Known_blocked_JA4_fingerprint";
                decision.risk_level = "High";
            } else if (decision.action == "ALLOW") {
                decision.reason = "Known_allowed_JA4_fingerprint";
                decision.risk_level = "Low";
            } else if (decision.action == "RATE_LIMIT") {
                decision.reason = "Suspicious_JA4_fingerprint";
                decision.risk_level = "Medium";
            }

            rules_[fingerprint] = decision;
        }
    }

    return true;
}

RuleDecision RuleEngine::decide(const std::string& ja4) const {
    auto it = rules_.find(ja4);
    if (it != rules_.end()) {
        return it->second;
    }

    return RuleDecision{};
}