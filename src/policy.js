class Rule {
    evaluate(request) {
        throw new Error("Must be implemented");
    }
}

class ObsoleteOperatingSystemsRule extends Rule {
    evaluate(request) {
        const obsoleteOperatingSystems = [
            { os: 'iOS', version: '3.2' },
            { os: 'Linux', version: 'x86_64' },
            { os: 'Windows', version: '98' },
            { os: 'Windows', version: '2000' },
            { os: 'Mac OS', version: '10.12.5 rv' }
            // Add more obsolete operating systems to this list as needed
        ];

        const userAgentOS = request.ClientRequestUserAgent.os;
        if (userAgentOS) {
            const osName = userAgentOS.name;
            const osVersion = userAgentOS.version;

            for (const obsoleteOS of obsoleteOperatingSystems) {
                if (osName === obsoleteOS.os && osVersion === obsoleteOS.version) {
                    return true; // Operating system is obsolete
                }
            }
        }
        return false; // Operating system is not obsolete
    }
}

class DeviceInformationAbsenceRule extends Rule {
    evaluate(request) {
        const device = request.ClientRequestUserAgent.device;

        return !device || !device.vendor || !device.model; // Device information is present and complete
    }
}

class MaliciousRequestPathRule extends Rule {
    evaluate(request) {
        const suspiciousPatterns = [
            /\.{2,}\/|\/\.{2,}/, // matches /../../boot.ini, /../../../etc/passwd, /../../../../windows/system32/cmd.exe
            /<script.*?>/i, // matches any requests containing <script> tags (case-insensitive)
            /<.*?>.*?<\/.*?>/i, // matches any requests containing HTML tags (case-insensitive)
            /\?.*?<.*?>/i, // matches any requests containing URL parameters with HTML tags (case-insensitive)
            /[;`(]+.*?(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE|SELECT|TRUNCATE).*?;/i, // matches possible SQL injection attacks
            /\b(UNION|SELECT|FROM|WHERE|JOIN|LIMIT|ORDER BY|GROUP BY|HAVING)\b/i, // matches SQL keywords
            /(;|<|>|'|")(.*)/, // matches possible XSS attacks using semicolons, angle brackets, quotes, or parentheses
            /\bjavascript\b/i, // matches requests containing the word "javascript" (case-insensitive)
            /\balert\b/i, // matches requests containing the word "alert" (case-insensitive)
            /\bconfirm\b/i, // matches requests containing the word "confirm" (case-insensitive)
            /\bprompt\b/i, // matches requests containing the word "prompt" (case-insensitive)
            /\bcmd\b/i, // matches requests containing the word "cmd" (case-insensitive)
            /\bshell\b/i, // matches requests containing the word "shell" (case-insensitive)
            /\bexec\b/i, // matches requests containing the word "exec" (case-insensitive)
            /\b system\b/i, // matches requests containing the word "system" (case-insensitive)
            /\bcat\b/i, // matches requests containing the word "cat" (case-insensitive)
        ];

        for (const pattern of suspiciousPatterns) {
            if (pattern.test(request.ClientRequestPath)) {
                return true; // Malicious request detected
            }
        }
        return false; // Request is not malicious
    }
}


class Policy {
    constructor() {
        this.rules = [new ObsoleteOperatingSystemsRule(), new DeviceInformationAbsenceRule(), new MaliciousRequestPathRule()];
    }

    analyze(traffic, firewall) {
        const results = [];

        traffic.forEach(request => {
            let allowed = true;
            let blockReason = '';

            for (const rule of this.rules) {
                if (rule.evaluate(request)) {
                    allowed = false;
                    blockReason = rule.constructor.name; // Get the name of the rule that blocked the request
                    break;
                }
            }

            if (!allowed) {
                results.push({ action: 'BLOCKED', reason: blockReason, request });
            } else if (!firewall.isAllowed(request.ClientIP, request.EdgeStartTimestamp)) {
                results.push({ action: 'BLOCKED_IP', request });
            } else {
                results.push({ action: 'ALLOWED', request });
            }
        });

        return results;
    }
}

module.exports = { Policy };