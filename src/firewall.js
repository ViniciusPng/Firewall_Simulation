class Firewall {
    constructor() {
        this.whitelist = new Set();
        this.blacklist = new Map();
        this.history = []; // Novo histórico de ações
    }

    addToWhitelist(identifier) {
        this.whitelist.add(identifier);
        this.logAction(`Added to whitelist: ${identifier}`); // Registra a ação no histórico
    }

    addToBlacklist(identifier) {
        const blockTime = new Date();
        this.blacklist.set(identifier, blockTime);
        this.logAction(`Added to blacklist: ${identifier} (blocked for 12 hours)`); // Registra a ação no histórico
    }

    isAllowed(identifier, shippingDate) {
        const action = `Received packet from ${identifier} at ${shippingDate}`;

        if (!this.checkRateLimiting(identifier, shippingDate)) {
            this.logAction(action, 'blocked', 'rate limiting', shippingDate);
            return false;
        }

        // Verifica se o IP/hostname está na whitelist
        if (this.whitelist.has(identifier)) {
            this.logAction(action, 'allowed', 'whitelisted', shippingDate);
            return true;
        }

        // Verifica se o IP/hostname está na blacklist
        if (this.blacklist.has(identifier)) {
            const blockTime = this.blacklist.get(identifier);
            const elapsed = (shippingDate - blockTime) / 1000 / 60 / 60; // Tempo em horas
            if (elapsed < 12) {
                this.logAction(action, 'blocked', 'blacklist', shippingDate);
                return false;
            }
            this.blacklist.delete(identifier); // Remove do bloqueio após 12 horas
            this.logAction(action, 'removed', 'blacklist', shippingDate);
        }

        this.logAction(action, 'allowed', 'default', shippingDate);
        return true;
    }

    checkRateLimiting(identifier, shippingDate) {
        const historyEntry = this.history.find(entry => entry.action.includes(identifier));
        if (historyEntry) {
            const shippingDateMs = new Date(shippingDate).getTime();
            const historyEntryTimestampMs = new Date(historyEntry.timestamp).getTime();
            console.log('shippingDate:', shippingDate);
            console.log('historyEntry.timestamp:', historyEntry.timestamp);
            const elapsed = (shippingDateMs - historyEntryTimestampMs) / 1000 / 60 / 60; // Tempo em horas
            console.log(elapsed);
            if (elapsed < 1) { // Verifica se a data da nova requisição está dentro de 1 hora da última requisição
                this.addToBlacklist(identifier, shippingDate); // Bloqueia o IP por 12 horas
                return false;
            }
        }
        return true;
    }

    logAction(action, type, reason, shippingDate) {
        this.history.push({
            timestamp: shippingDate,
            action,
            type,
            reason
        });
    }

    getHistory() {
        return this.history; // Retorna o histórico de ações
    }
}

module.exports = new Firewall();