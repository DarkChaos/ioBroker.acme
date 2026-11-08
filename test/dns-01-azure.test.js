'use strict';

const { expect } = require('chai');
const { create } = require('../build/lib/dns-01-azure');

const OPTIONS = {
    tenantId: 'tenant-id',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    subscriptionId: 'subscription-id',
};
const CHALLENGE = {
    dnsHost: '_acme-challenge.sub.example.com',
    dnsAuthorization: 'VALUE-A',
    identifier: { value: 'sub.example.com' },
};
const ZONE = {
    id: '/subscriptions/subscription-id/resourceGroups/dns-rg/providers/Microsoft.Network/dnsZones/example.com',
    name: 'example.com',
    properties: { zoneType: 'Public' },
};

function recorder(handler) {
    const calls = [];
    const fn = (url, init = {}) => {
        const method = init.method || 'GET';
        const call = { method, url, headers: init.headers, body: init.body };
        calls.push(call);
        const result = handler(call) || {};
        return Promise.resolve({
            ok: result.ok !== false,
            status: result.status || 200,
            statusText: result.statusText || 'OK',
            text: () => Promise.resolve(result.body === undefined ? '' : JSON.stringify(result.body)),
        });
    };
    fn.calls = calls;
    return fn;
}

function azureFetch(recordSet) {
    return recorder(({ method, url }) => {
        if (url.includes('/oauth2/v2.0/token')) {
            return { body: { access_token: 'access-token', expires_in: 3600 } };
        }
        if (url.includes('/dnsZones?')) {
            return { body: { value: [ZONE] } };
        }
        if (method === 'GET' && url.includes('/TXT?')) {
            return recordSet ? { body: recordSet } : { ok: false, status: 404, statusText: 'Not Found' };
        }
        return {};
    });
}

describe('dns-01-azure', () => {
    it('requires all service-principal credentials', () => {
        expect(() => create({})).to.throw(/tenantId, clientId, clientSecret, subscriptionId/);
    });

    it('authenticates, finds the longest matching public zone, and preserves existing TXT values', async () => {
        const existing = { properties: { TTL: 300, TXTRecords: [{ value: ['EXISTING'] }] } };
        const fetch = azureFetch(existing);
        await create({ ...OPTIONS, fetch }).set({ challenge: CHALLENGE });

        const tokenRequest = fetch.calls.find(call => call.url.includes('/oauth2/v2.0/token'));
        expect(tokenRequest.body).to.contain('client_id=client-id');
        expect(tokenRequest.body).to.contain('client_secret=client-secret');
        const put = fetch.calls.find(call => call.method === 'PUT');
        expect(put.url).to.contain('/dnsZones/example.com/_acme-challenge.sub/TXT');
        expect(put.headers.Authorization).to.equal('Bearer access-token');
        expect(JSON.parse(put.body)).to.deep.equal({
            properties: { TTL: 300, TXTRecords: [{ value: ['EXISTING'] }, { value: ['VALUE-A'] }] },
        });
    });

    it('removes only the challenge value and leaves other TXT values', async () => {
        const existing = {
            properties: { TTL: 300, TXTRecords: [{ value: ['VALUE-A'] }, { value: ['VALUE-B'] }] },
        };
        const fetch = azureFetch(existing);
        await create({ ...OPTIONS, fetch }).remove({ challenge: CHALLENGE });

        const put = fetch.calls.find(call => call.method === 'PUT');
        expect(put).to.exist;
        expect(JSON.parse(put.body)).to.deep.equal({
            properties: { TTL: 300, TXTRecords: [{ value: ['VALUE-B'] }] },
        });
        expect(fetch.calls.some(call => call.method === 'DELETE')).to.equal(false);
    });

    it('deletes the record set when the challenge was its only value', async () => {
        const fetch = azureFetch({ properties: { TTL: 60, TXTRecords: [{ value: ['VALUE-A'] }] } });
        await create({ ...OPTIONS, fetch }).remove({ challenge: CHALLENGE });
        expect(fetch.calls.some(call => call.method === 'DELETE')).to.equal(true);
    });

    it('reports an error when no public zone matches', async () => {
        const fetch = recorder(({ url }) => {
            if (url.includes('/oauth2/v2.0/token')) return { body: { access_token: 'access-token' } };
            return { body: { value: [{ ...ZONE, name: 'unrelated.org' }] } };
        });
        try {
            await create({ ...OPTIONS, fetch }).set({ challenge: CHALLENGE });
            expect.fail('should have thrown');
        } catch (err) {
            expect(err.message).to.contain('No Azure DNS zone found');
        }
    });
});