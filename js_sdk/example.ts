import {ReclaimSDK, ReclaimError, ReclaimProtocolError} from './src';
import path from 'path';

async function main() {
    // Create and initialize SDK
    // By default, looks for libreclaim.so in ../lib/libreclaim.so relative to dist/
    const sdk = new ReclaimSDK(path.resolve(__dirname, '../lib/libreclaim.so'));
    sdk.init();

    console.log('Reclaim SDK Version:', sdk.getVersion());

    // Initialize ZK circuits (required for OPRF-based redactions)
    const circuitsPath = path.resolve(__dirname, '../circuits');
    console.log('Initializing ZK circuits from:', circuitsPath);
    try {
        sdk.initializeZKCircuits(circuitsPath);
        console.log('ZK circuits initialized successfully');
    } catch (err) {
        console.error('Failed to initialize ZK circuits:', err);
        return;
    }

    // Example provider request
    const request = {
        "name": "http",
        "params": {
            "url": "https://vpic.nhtsa.dot.gov/",
            "method": "GET",
            "responseMatches": [

                {
                    "value": "{{addr}}",
                    "type": "contains"
                }
            ],
            "responseRedactions": [

                {
                    "xPath": "/html/body/footer/div[2]/div/div[1]/ul[3]/li[2]/a",
                    "regex": "href=\"https://(?<addr>www.trafficsafetymarketing.gov)/\"",
                    "hash": "oprf"
                }

            ],
            "paramValues": {
                "addr": "www.trafficsafetymarketing.gov",
            },
        },
        "secretParams": {
            "headers": {
                "accept": "application/json, text/plain, */*",
            },
        }
    };

    // Optional configuration
    const config = {
        teek_url: 'ws://localhost:8080/ws',
        teet_url: 'ws://localhost:8081/ws',
        timeout_ms: 30000,
    };

    try {
        console.log('Executing protocol...');
        const result = await sdk.executeProtocolAsync(request, config);

        console.log('Protocol completed successfully!');
        console.log('Claim:', JSON.stringify(result.claim, null, 2));
        console.log('Signatures:', JSON.stringify(result.signatures, null, 2));
    } catch (err) {
        if (err instanceof ReclaimProtocolError) {
            console.error('Protocol error:', err.message);
            console.error('Error code:', ReclaimError[err.code]);
        } else {
            console.error('Unexpected error:', err);
        }
    }
}

main().catch(console.error);
