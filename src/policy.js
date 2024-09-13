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
                    return true;
                }
            }
        }
        return false;
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
            /\.{2,}\/|\/\.{2,}/,
            /<script.*?>/i,
            /<.*?>.*?<\/.*?>/i,
            /\?.*?<.*?>/i,
            /[;`(]+.*?(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE|SELECT|TRUNCATE).*?;/i,
            /\b(UNION|SELECT|FROM|WHERE|JOIN|LIMIT|ORDER BY|GROUP BY|HAVING)\b/i,
            /(;|<|>|'|")(.*)/,
            /\bjavascript\b/i,
            /\balert\b/i,
            /\bconfirm\b/i,
            /\bprompt\b/i,
            /\bcmd\b/i,
            /\bshell\b/i,
            /\bexec\b/i,
            /\b system\b/i,
            /\bcat\b/i,
        ];

        for (const pattern of suspiciousPatterns) {
            if (pattern.test(request.ClientRequestPath)) {
                return true;
            }
        }
        return false;
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
                    blockReason = rule.constructor.name;
                    break;
                }
            }

            if (!allowed) {
                results.push({ action: 'BLOCKED', reason: blockReason, request });
            } else {
                const { allowed, reason } = firewall.isAllowed(request.ClientIP, request.EdgeStartTimestamp);
                if (!allowed) {
                    results.push({ action: 'BLOCKED_IP', reason, request });
                } else {
                    results.push({ action: 'ALLOWED', reason, request });
                }
            }
        });

        return results;
    }
}

module.exports = { Policy };