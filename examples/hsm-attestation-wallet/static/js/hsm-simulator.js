/**
 * Hardware Security Module Simulator
 * 
 * Simulates HSM operations including key generation, signing,
 * and attestation certificate creation.
 */

class HSMSimulator {
    constructor() {
        this.crypto = new CryptoUtils();
        this.deviceId = null;
        this.keys = new Map(); // keyId -> {privateKey, publicKey, metadata}
        this.securityState = 'secure';
        this.tamperDetected = false;
        this.bootCount = 1;
        this.attestationRootKey = null;
        this.deviceCertificate = null;
        this.initialized = false;
        
        this.eventCallbacks = [];
    }

    /**
     * Initialize the HSM
     */
    async initialize() {
        try {
            this.log('Initializing HSM...');
            
            // Generate device ID
            this.deviceId = `hsm_${this.crypto.generateRandomHex(8)}`;
            
            // Generate attestation root key
            this.attestationRootKey = await this.crypto.generateECKeyPair();
            
            // Create device certificate
            await this.generateDeviceCertificate();
            
            this.initialized = true;
            this.securityState = 'secure';
            
            this.log(`HSM initialized successfully`, 'success');
            this.log(`Device ID: ${this.deviceId}`, 'info');
            this.log(`Security state: ${this.securityState}`, 'info');
            
            this.notifyEvent('initialized', {
                deviceId: this.deviceId,
                securityState: this.securityState
            });
            
            return {
                deviceId: this.deviceId,
                securityState: this.securityState,
                tamperDetected: this.tamperDetected
            };
            
        } catch (error) {
            this.log(`HSM initialization failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Generate device certificate
     */
    async generateDeviceCertificate() {
        try {
            // Simulate X.509 certificate structure
            const now = Date.now();
            const publicKeyJWK = await this.crypto.exportPublicKeyJWK(this.attestationRootKey.publicKey);
            
            this.deviceCertificate = {
                version: 3,
                serialNumber: this.crypto.generateRandomHex(16),
                subject: {
                    C: 'US',
                    ST: 'CA', 
                    L: 'San Francisco',
                    O: 'Wallet HSM',
                    CN: `HSM-${this.deviceId}`
                },
                issuer: {
                    C: 'US',
                    ST: 'CA',
                    L: 'San Francisco', 
                    O: 'Wallet HSM Root CA',
                    CN: 'Wallet HSM Root CA'
                },
                notBefore: now,
                notAfter: now + (365 * 24 * 60 * 60 * 1000), // 1 year
                publicKey: publicKeyJWK,
                signature: await this.crypto.generateRandomHex(64), // Mock signature
                extensions: {
                    keyUsage: ['digitalSignature', 'keyCertSign'],
                    basicConstraints: { CA: true },
                    subjectKeyIdentifier: await this.crypto.generateKeyThumbprint(publicKeyJWK)
                }
            };
            
            this.log('Device certificate generated', 'success');
            
        } catch (error) {
            this.log(`Device certificate generation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Generate a new key pair
     */
    async generateKeyPair(keyId = null, algorithm = 'EC-P256') {
        if (!this.initialized) {
            throw new Error('HSM not initialized');
        }

        if (this.tamperDetected) {
            throw new Error('HSM tamper detected - operations disabled');
        }

        try {
            keyId = keyId || `key_${this.crypto.generateRandomHex(8)}`;
            
            this.log(`Generating key pair: ${keyId}`);
            
            const keyPair = await this.crypto.generateECKeyPair();
            const publicKeyJWK = await this.crypto.exportPublicKeyJWK(keyPair.publicKey);
            
            const metadata = {
                keyId,
                algorithm,
                keyUsage: ['sign', 'authenticate'],
                createdAt: Date.now(),
                hardwareBacked: true,
                securityLevel: 'hardware'
            };

            this.keys.set(keyId, {
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                publicKeyJWK,
                metadata
            });

            this.log(`Key pair generated successfully: ${keyId}`, 'success');
            this.log(`Public key thumbprint: ${await this.crypto.generateKeyThumbprint(publicKeyJWK)}`, 'info');

            this.notifyEvent('keyGenerated', { keyId, metadata });

            return keyId;

        } catch (error) {
            this.log(`Key generation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Sign data with a specific key
     */
    async signData(keyId, data) {
        if (!this.initialized) {
            throw new Error('HSM not initialized');
        }

        if (this.tamperDetected) {
            throw new Error('HSM tamper detected - operations disabled');
        }

        if (!this.keys.has(keyId)) {
            throw new Error(`Key not found: ${keyId}`);
        }

        try {
            const keyData = this.keys.get(keyId);
            const signature = await this.crypto.signData(keyData.privateKey, data);
            
            this.log(`Data signed with key: ${keyId}`, 'success');
            
            this.notifyEvent('dataSigned', { keyId, dataLength: data.length });
            
            return signature;

        } catch (error) {
            this.log(`Signing failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Generate key attestation certificate
     */
    async generateKeyAttestation(keyId) {
        if (!this.initialized) {
            throw new Error('HSM not initialized');
        }

        if (!this.keys.has(keyId)) {
            throw new Error(`Key not found: ${keyId}`);
        }

        try {
            const keyData = this.keys.get(keyId);
            const now = Date.now();
            
            // Create attestation certificate for the key
            const attestationCert = {
                version: 3,
                serialNumber: this.crypto.generateRandomHex(16),
                subject: {
                    CN: `Key-${keyId}`,
                    O: `HSM-${this.deviceId}`
                },
                issuer: this.deviceCertificate.subject,
                notBefore: now,
                notAfter: now + (30 * 24 * 60 * 60 * 1000), // 30 days
                publicKey: keyData.publicKeyJWK,
                signature: await this.crypto.generateRandomHex(64), // Mock signature
                extensions: {
                    keyUsage: ['digitalSignature'],
                    basicConstraints: { CA: false },
                    subjectKeyIdentifier: await this.crypto.generateKeyThumbprint(keyData.publicKeyJWK),
                    authorityKeyIdentifier: this.deviceCertificate.extensions.subjectKeyIdentifier,
                    // Custom HSM extensions
                    hsmExtensions: {
                        hardwareBacked: true,
                        securityLevel: 'hardware',
                        deviceId: this.deviceId,
                        bootCount: this.bootCount,
                        tamperDetected: this.tamperDetected
                    }
                }
            };

            // Store attestation certificate in key metadata
            keyData.metadata.attestationCertificate = attestationCert;
            
            this.log(`Key attestation certificate generated for: ${keyId}`, 'success');
            
            this.notifyEvent('attestationGenerated', { keyId, certificate: attestationCert });
            
            return attestationCert;

        } catch (error) {
            this.log(`Attestation generation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Get device attestation information
     */
    getDeviceAttestation() {
        if (!this.initialized) {
            throw new Error('HSM not initialized');
        }

        return {
            deviceId: this.deviceId,
            deviceCertificate: this.deviceCertificate,
            securityState: this.securityState,
            bootCount: this.bootCount,
            tamperDetected: this.tamperDetected,
            firmwareVersion: '1.0.0-sim',
            keyCount: this.keys.size,
            attestationRootPublicKey: this.deviceCertificate.publicKey
        };
    }

    /**
     * Get public key in JWK format
     */
    getPublicKeyJWK(keyId) {
        if (!this.keys.has(keyId)) {
            throw new Error(`Key not found: ${keyId}`);
        }

        return this.keys.get(keyId).publicKeyJWK;
    }

    /**
     * Get key metadata
     */
    getKeyMetadata(keyId) {
        if (!this.keys.has(keyId)) {
            throw new Error(`Key not found: ${keyId}`);
        }

        return this.keys.get(keyId).metadata;
    }

    /**
     * List all keys
     */
    listKeys() {
        const keyList = [];
        for (const [keyId, keyData] of this.keys.entries()) {
            keyList.push({
                keyId,
                metadata: keyData.metadata
            });
        }
        return keyList;
    }

    /**
     * Check if a key exists
     */
    hasKey(keyId) {
        return this.keys.has(keyId);
    }

    /**
     * Simulate tamper detection
     */
    simulateTamperDetection() {
        this.tamperDetected = true;
        this.securityState = 'compromised';
        
        this.log('🚨 TAMPER DETECTED - HSM operations disabled', 'error');
        
        this.notifyEvent('tamperDetected', {
            deviceId: this.deviceId,
            timestamp: Date.now()
        });
    }

    /**
     * Reset HSM (for demo purposes)
     */
    async reset() {
        this.log('Resetting HSM...');
        
        this.keys.clear();
        this.tamperDetected = false;
        this.securityState = 'secure';
        this.bootCount++;
        this.initialized = false;
        
        // Re-initialize
        await this.initialize();
        
        this.log('HSM reset complete', 'success');
        
        this.notifyEvent('reset', {
            deviceId: this.deviceId,
            bootCount: this.bootCount
        });
    }

    /**
     * Add event listener
     */
    addEventListener(callback) {
        this.eventCallbacks.push(callback);
    }

    /**
     * Notify event listeners
     */
    notifyEvent(type, data) {
        const event = {
            type,
            timestamp: Date.now(),
            deviceId: this.deviceId,
            data
        };

        this.eventCallbacks.forEach(callback => {
            try {
                callback(event);
            } catch (error) {
                console.error('Error in HSM event callback:', error);
            }
        });
    }

    /**
     * Log HSM operations
     */
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[HSM ${timestamp}] ${message}`);
        
        // Notify UI
        if (window.UIController) {
            window.UIController.addLog('hsm', timestamp, message, type);
        }
    }

    /**
     * Get HSM status summary
     */
    getStatus() {
        return {
            initialized: this.initialized,
            deviceId: this.deviceId,
            securityState: this.securityState,
            tamperDetected: this.tamperDetected,
            keyCount: this.keys.size,
            bootCount: this.bootCount
        };
    }

    /**
     * Get detailed key information for display
     */
    getDetailedKeyInfo() {
        const keyDetails = [];
        
        for (const [keyId, keyData] of this.keys.entries()) {
            const metadata = keyData.metadata;
            const publicKeyJWK = keyData.publicKeyJWK;
            
            keyDetails.push({
                keyId: keyId,
                algorithm: metadata.algorithm,
                keyUsage: metadata.keyUsage.join(', '),
                createdAt: new Date(metadata.createdAt).toLocaleString(),
                hardwareBacked: metadata.hardwareBacked,
                securityLevel: metadata.securityLevel,
                keyType: publicKeyJWK.kty,
                curve: publicKeyJWK.crv,
                thumbprint: publicKeyJWK.kid || 'generating...',
                hasAttestation: !!metadata.attestationCertificate,
                publicKeyFingerprint: this.getKeyFingerprint(publicKeyJWK)
            });
        }
        
        return keyDetails;
    }

    /**
     * Get a shorter fingerprint of the public key for display
     */
    getKeyFingerprint(publicKeyJWK) {
        try {
            const keyStr = JSON.stringify({
                kty: publicKeyJWK.kty,
                crv: publicKeyJWK.crv,
                x: publicKeyJWK.x,
                y: publicKeyJWK.y
            });
            
            // Simple hash for display (not cryptographically secure)
            let hash = 0;
            for (let i = 0; i < keyStr.length; i++) {
                const char = keyStr.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32-bit integer
            }
            
            return Math.abs(hash).toString(16).substring(0, 8).toUpperCase();
        } catch (error) {
            return 'UNKNOWN';
        }
    }

    /**
     * Display detailed HSM information
     */
    displayDetailedInfo() {
        if (!this.initialized) {
            this.log('HSM not initialized - cannot display details', 'warning');
            return;
        }

        const status = this.getStatus();
        const keyDetails = this.getDetailedKeyInfo();
        const deviceAttestation = this.getDeviceAttestation();

        this.log('=== HSM DETAILED INFORMATION ===', 'info');
        this.log(`Device ID: ${status.deviceId}`, 'info');
        this.log(`Security State: ${status.securityState}`, 'info');
        this.log(`Boot Count: ${status.bootCount}`, 'info');
        this.log(`Tamper Status: ${status.tamperDetected ? '🚨 DETECTED' : '✅ Clean'}`, status.tamperDetected ? 'error' : 'success');
        this.log(`Firmware Version: ${deviceAttestation.firmwareVersion}`, 'info');
        this.log(`Total Keys: ${status.keyCount}`, 'info');
        
        if (keyDetails.length > 0) {
            this.log('', 'info'); // Empty line
            this.log('=== GENERATED KEYS ===', 'info');
            
            keyDetails.forEach((key, index) => {
                this.log(`Key #${index + 1}: ${key.keyId}`, 'info');
                this.log(`  ├─ Algorithm: ${key.algorithm} (${key.keyType}-${key.curve})`, 'info');
                this.log(`  ├─ Usage: ${key.keyUsage}`, 'info');
                this.log(`  ├─ Created: ${key.createdAt}`, 'info');
                this.log(`  ├─ Security: ${key.securityLevel} (${key.hardwareBacked ? 'Hardware Backed' : 'Software'})`, 'info');
                this.log(`  ├─ Fingerprint: ${key.publicKeyFingerprint}`, 'info');
                this.log(`  └─ Attestation: ${key.hasAttestation ? '✅ Available' : '⏳ Not Generated'}`, key.hasAttestation ? 'success' : 'warning');
                
                if (index < keyDetails.length - 1) {
                    this.log('', 'info'); // Spacing between keys
                }
            });
        } else {
            this.log('No keys generated yet', 'warning');
        }
        
        this.log('=== DEVICE CERTIFICATE ===', 'info');
        if (this.deviceCertificate) {
            this.log(`Serial: ${this.deviceCertificate.serialNumber}`, 'info');
            this.log(`Subject: ${this.deviceCertificate.subject.CN}`, 'info');
            this.log(`Valid Until: ${new Date(this.deviceCertificate.notAfter).toLocaleDateString()}`, 'info');
            this.log(`Key ID: ${this.deviceCertificate.extensions.subjectKeyIdentifier}`, 'info');
        }
        
        this.log('=== END HSM INFO ===', 'info');
    }
}

// Export for use in other modules
window.HSMSimulator = HSMSimulator;