"use strict";
/*
 * DNS-01 challenge handler for Azure DNS.
 *
 * Uses the Azure Resource Manager API with a service principal. TXT records
 * are updated as record sets, so existing values are preserved on add/remove.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.Azure01Challenge = void 0;
exports.create = create;
const DEFAULT_TTL = 60;
const DNS_API_VERSION = '2018-05-01';
const ARM_BASE_URL = 'https://management.azure.com';
class Azure01Challenge {
    tenantId;
    clientId;
    clientSecret;
    subscriptionId;
    ttl;
    log;
    doFetch;
    zonesCache = null;
    accessToken = null;
    tokenExpiresAt = 0;
    constructor(options) {
        const missing = ['tenantId', 'clientId', 'clientSecret', 'subscriptionId'].filter(key => !options?.[key]);
        if (missing.length) {
            throw new Error(`Azure DNS-01 needs ${missing.join(', ')} in the DNS-01 configuration`);
        }
        this.tenantId = options.tenantId;
        this.clientId = options.clientId;
        this.clientSecret = options.clientSecret;
        this.subscriptionId = options.subscriptionId;
        this.ttl = options.ttl || DEFAULT_TTL;
        this.log = options.log || (() => { });
        this.doFetch = options.fetch || fetch;
    }
    async getAccessToken() {
        if (this.accessToken && Date.now() < this.tokenExpiresAt) {
            return this.accessToken;
        }
        const body = new URLSearchParams({
            client_id: this.clientId,
            client_secret: this.clientSecret,
            scope: 'https://management.azure.com/.default',
            grant_type: 'client_credentials',
        });
        const response = await this.doFetch(`https://login.microsoftonline.com/${encodeURIComponent(this.tenantId)}/oauth2/v2.0/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
            body: body.toString(),
        });
        const text = await response.text();
        if (!response.ok) {
            throw new Error(`Azure token request failed: ${response.status} ${response.statusText} ${text}`.trim());
        }
        const result = JSON.parse(text);
        this.accessToken = result.access_token;
        this.tokenExpiresAt = Date.now() + Number(result.expires_in || 3600) * 1000 - 60_000;
        return this.accessToken;
    }
    async request(method, url, body, allowNotFound = false) {
        const headers = {
            Authorization: `Bearer ${await this.getAccessToken()}`,
            Accept: 'application/json',
        };
        if (body !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        const response = await this.doFetch(url, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (allowNotFound && response.status === 404) {
            return null;
        }
        const text = await response.text();
        if (!response.ok) {
            throw new Error(`Azure ${method} ${url} failed: ${response.status} ${response.statusText} ${text}`.trim());
        }
        return text ? JSON.parse(text) : null;
    }
    async getZones() {
        if (this.zonesCache) {
            return this.zonesCache;
        }
        const zones = [];
        let url = `${ARM_BASE_URL}/subscriptions/${encodeURIComponent(this.subscriptionId)}/providers/Microsoft.Network/dnsZones?api-version=${DNS_API_VERSION}`;
        while (url) {
            const result = await this.request('GET', url);
            zones.push(...(result?.value || []));
            url = result?.nextLink || '';
        }
        this.zonesCache = zones.filter(zone => !zone.properties?.zoneType || zone.properties.zoneType === 'Public');
        return this.zonesCache;
    }
    async resolveZone(challenge) {
        const host = (challenge.dnsHost || `_acme-challenge.${challenge.identifier?.value ?? ''}`).toLowerCase();
        const zones = await this.getZones();
        const candidates = challenge.dnsZone
            ? zones.filter(zone => zone.name.toLowerCase() === challenge.dnsZone.toLowerCase())
            : zones
                .filter(zone => host === zone.name.toLowerCase() || host.endsWith(`.${zone.name.toLowerCase()}`))
                .sort((a, b) => b.name.length - a.name.length);
        const zone = candidates[0];
        if (!zone) {
            throw new Error(`No Azure DNS zone found for ${host}`);
        }
        return zone;
    }
    recordUrl(zone, host) {
        const zoneName = zone.name.toLowerCase();
        const recordName = host.toLowerCase() === zoneName ? '@' : host.slice(0, -(zoneName.length + 1));
        return `${ARM_BASE_URL}${zone.id}/${encodeURIComponent(recordName)}/TXT?api-version=${DNS_API_VERSION}`;
    }
    init() {
        return Promise.resolve(null);
    }
    async zones(data) {
        const found = new Set();
        for (const host of data?.dnsHosts || []) {
            try {
                found.add((await this.resolveZone({ dnsHost: host })).name);
            }
            catch {
                // set() reports hosts that cannot be placed in an Azure zone.
            }
        }
        return [...found];
    }
    async set(data) {
        const { challenge } = data;
        const host = challenge.dnsHost;
        const zone = await this.resolveZone(challenge);
        const url = this.recordUrl(zone, host);
        const current = await this.request('GET', url, undefined, true);
        const records = current?.properties?.TXTRecords || [];
        if (!records.some(record => record.value.includes(challenge.dnsAuthorization))) {
            records.push({ value: [challenge.dnsAuthorization] });
        }
        this.log(`adding TXT ${host} in Azure zone ${zone.name}`);
        await this.request('PUT', url, {
            properties: { TTL: current?.properties?.TTL || this.ttl, TXTRecords: records },
        });
        return null;
    }
    async get(data) {
        const { challenge } = data;
        const zone = await this.resolveZone(challenge);
        const current = await this.request('GET', this.recordUrl(zone, challenge.dnsHost), undefined, true);
        const present = current?.properties?.TXTRecords?.some(record => record.value.includes(challenge.dnsAuthorization));
        return present ? { dnsAuthorization: challenge.dnsAuthorization } : null;
    }
    async remove(data) {
        const { challenge } = data;
        const host = challenge.dnsHost;
        const zone = await this.resolveZone(challenge);
        const url = this.recordUrl(zone, host);
        const current = await this.request('GET', url, undefined, true);
        if (!current?.properties?.TXTRecords) {
            return null;
        }
        const remaining = current.properties.TXTRecords.filter(record => !record.value.includes(challenge.dnsAuthorization));
        if (remaining.length === current.properties.TXTRecords.length) {
            return null;
        }
        this.log(`removing TXT ${host} from Azure zone ${zone.name}`);
        if (!remaining.length) {
            await this.request('DELETE', url);
        }
        else {
            await this.request('PUT', url, {
                properties: { TTL: current.properties.TTL || this.ttl, TXTRecords: remaining },
            });
        }
        return null;
    }
}
exports.Azure01Challenge = Azure01Challenge;
function create(options) {
    return new Azure01Challenge(options);
}
