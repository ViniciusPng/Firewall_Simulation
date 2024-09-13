class Firewall {
    constructor() {
        this.whitelist = new Set();
        this.blacklist = new Map();
        this.tempBlocks = new Map();
        this.history = [];
    }

    addToWhitelist(identifier) {
        this.whitelist.add(identifier);
        this.logAction(`Added to whitelist: ${identifier}`);
    }

    addToBlacklist(identifier) {
        const blockTime = new Date();
        this.blacklist.set(identifier, blockTime);
        this.logAction(`Added to blacklist: ${identifier}`);
    }

    addToTempBlock(identifier, shippingDate) {
        const date = new Date(shippingDate); // Parse shippingDate as a Date object
        const blockTime = date.getTime() + 12 * 60 * 60 * 1000; // Add 12 hours to the shippingDate timestamp
        this.tempBlocks.set(identifier, blockTime);
        this.logAction(`Added to temp block: ${identifier} (blocked for 12 hours)`);
    }

    isAllowed(identifier, shippingDate) {
        const action = `Received packet from ${identifier} at ${shippingDate}`;

        // Verifica se o IP/hostname está na whitelist
        if (this.whitelist.has(identifier)) {
            this.logAction(action, 'allowed', 'whitelisted', shippingDate);
            return { allowed: true, reason: 'Whitelisted' };
        }

        // Verifica se o IP/hostname está na blacklist
        if (this.blacklist.has(identifier)) {
            this.logAction(action, 'blocked', 'blacklist', shippingDate);
            return { allowed: false, reason: 'Blacklisted' };
        }

        // Se o IP não está na whitelist ou blacklist, prossegue com as outras verificações
        if (!this.checkRateLimiting(identifier, shippingDate)) {
            this.logAction(action, 'blocked', 'rate limiting', shippingDate);
            return { allowed: false, reason: 'Rate limiting' };
        }

        // Verifica se o IP/hostname está na lista de blocks temporarios
        if (this.tempBlocks.has(identifier)) {
            const blockTime = this.tempBlocks.get(identifier);
            const elapsed = (shippingDate - blockTime) / 1000 / 60 / 60;
            if (elapsed < 12) {
                this.logAction(action, 'blocked', 'temp block', shippingDate);
                return { allowed: false, reason: 'Temporarily blocked' };
            } else {
                this.tempBlocks.delete(identifier); // Remove do bloqueio após 12 horas
                this.logAction(action, 'removed', 'temp block', shippingDate);
            }
        }

        this.logAction(action, 'allowed', 'default', shippingDate);
        return { allowed: true, reason: 'Default allow' };
    }

    checkRateLimiting(identifier, shippingDate) {
        const historyEntry = this.history.find(entry => entry.action.includes(identifier));
        if (historyEntry) {
            const shippingDateMs = new Date(shippingDate).getTime();
            const historyEntryTimestampMs = new Date(historyEntry.timestamp).getTime();
            const elapsed = (shippingDateMs - historyEntryTimestampMs) / 1000 / 60 / 60;
            if (elapsed < 1) {
                this.addToTempBlock(identifier, shippingDate); // Bloqueia o IP por 12 horas
                return false;
            } else if (this.history.some(entry => entry.action.includes(identifier) && (shippingDateMs - new Date(entry.timestamp).getTime()) / 1000 / 60 / 60 < 1)) {
                // Verifica se há um pacote enviado na última hora
                this.addToTempBlock(identifier, shippingDate); // Bloqueia o IP por 12 horas
                return false;
            } else if (this.tempBlocks.has(identifier) && (shippingDateMs - this.tempBlocks.get(identifier)) / 1000 / 60 / 60 < 12) {
                // Verifica se o usuário está tentando fazer uma nova requisição durante o período de bloqueio
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