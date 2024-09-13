const fs = require('fs');
const firewall = require('./src/firewall');
const traffic = require('./src/traffic');
const { Policy } = require('./src/policy');
const { logAction } = require('./src/logger');

const whitelist = traffic.loadList('./data/whitelist.json');
const blacklist = traffic.loadList('./data/blacklist.json');

whitelist.forEach(item => {
    firewall.addToWhitelist(item);
});
blacklist.forEach(item => {
    firewall.addToBlacklist(item);
});

// Lê o tráfego atualizado
const trafficData = traffic.parseTraffic('./data/csvjson.json');
traffic.userAgentAnalyzer(trafficData)

const policyInstance = new Policy();

// Aplica políticas de segurança
const results = policyInstance.analyze(trafficData, firewall);

results.forEach(result => {
    logAction(result.action, result.reason, result.request);
});
console.log(firewall.getHistory())
// Write the history to a JSON file
fs.writeFileSync('firewall_history.json', JSON.stringify(firewall.getHistory(), null, 2));