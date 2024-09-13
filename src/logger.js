const fs = require('fs');

function logAction(action, reason, details) {
    let logMessage = `${details.EdgeStartTimestamp} - ${action}`;
    if (reason) {
        logMessage += ` (${reason})`;
    }
    logMessage += `: ${JSON.stringify(details)}\n`;
    fs.appendFileSync('firewall.log', logMessage);
}


module.exports = { logAction };
