const fs = require('fs');
const UAParser = require('ua-parser-js');

function parseTraffic(filePath) {
    const rawData = fs.readFileSync(filePath);
    return JSON.parse(rawData);
}

function loadList(filePath) {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
}

function userAgentAnalyzer(traffic) {
    const parser = new UAParser();

    traffic.forEach((request, index) => {
        parser.setUA(request.ClientRequestUserAgent);
        const result = parser.getResult();
        traffic[index].ClientRequestUserAgent = result;
    });

    return traffic;
}

module.exports = { parseTraffic, loadList, userAgentAnalyzer };
