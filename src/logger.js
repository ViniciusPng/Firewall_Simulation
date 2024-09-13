const fs = require('fs');

function logAction(action, reason, details) {
    let logMessage = `${new Date().toISOString()} - ${action}`;
    if (reason) {
        logMessage += ` (${reason})`; // Add the reason in parentheses
    }
    logMessage += `: ${JSON.stringify(details)}\n`;
    fs.appendFileSync('firewall.log', logMessage);
}

module.exports = { logAction };
