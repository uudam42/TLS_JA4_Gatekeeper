#ifndef RULES_H
#define RULES_H

#include <string>
#include <unordered_map>

struct RuleDecision {
    std::string action = "ALLOW";
    std::string reason = "No matching rule";
    std::string risk_level = "Low";
};

class RuleEngine {
public:
    bool load_rules(const std::string& file_path);
    RuleDecision decide(const std::string& ja4) const;

private:
    std::unordered_map<std::string, RuleDecision> rules_;
};

#endif