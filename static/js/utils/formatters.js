window.AppFormattersUtil = {
    methods: {
        formatOsLabel(osType, osVer) {
            const type = osType || 'Unknown';
            return osVer ? `${type}` : type;
        },

        formatAddress(addr) {
            if (!addr) return '-';
            const raw = String(addr);
            const parts = raw.split(':');
            if (parts.length >= 2) return parts.slice(0, -1).join(':') || raw;
            return raw;
        },

        buildPromptLabel(conn) {
            if (!conn) return '$';
            return conn.hostname || 'host';
        },

        formatBytes(size) {
            const value = Number(size || 0);
            if (value < 1024) return `${value} B`;
            if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`;
            if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB`;
            return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
        },

        formatDateTimeStandard(value) {
            const text = String(value || '').trim();
            if (!text) return '-';

            const normalized = text.replace('T', ' ').split('.')[0];
            return normalized || '-';
        },

    }
}