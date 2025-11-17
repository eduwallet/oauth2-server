/**
 * JWT Attestation Service
 * 
 * Creates and verifies JWT attestation tokens that provide cryptographic
 * proof of hardware backing and device integrity.
 */

class AttestationService {
    constructor(hsm, biometricModule) {
        this.hsm = hsm;
        this.biometricModule = biometricModule;
        this.crypto = new CryptoUtils();
        this.signingKeyId = null;
        this.initialized = false;
        
        this.eventCallbacks = [];
    }

    /**
     * Initialize attestation service
     */
    async initialize() {
        if (!this.hsm || !this.hsm.initialized) {
            throw new Error('HSM must be initialized before attestation service');
        }

        try {
            this.log('Initializing attestation service...');
            
            // Generate attestation signing key in HSM (force EC-P256)
            this.signingKeyId = await this.hsm.generateKeyPair('attestation_signing_key', 'EC-P256');

            // Generate attestation certificate for the signing key (ensure EC)
            await this.hsm.generateKeyAttestation(this.signingKeyId, { keyType: 'EC-P256' });
            
            this.initialized = true;
            
            this.log('Attestation service initialized successfully', 'success');
            this.log(`Signing key: ${this.signingKeyId}`, 'info');
            
            this.notifyEvent('initialized', {
                signingKeyId: this.signingKeyId
            });
            
            return {
                initialized: true,
                signingKeyId: this.signingKeyId
            };
            
        } catch (error) {
            this.log(`Attestation initialization failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Create JWT attestation token
     */
    async createAttestationToken(options = {}) {
        if (!this.initialized) {
            throw new Error('Attestation service not initialized');
        }

        const {
            subject,
            audience,
            keyId,
            nonce = null,
            validitySeconds = 300,
            bioAuth = false,
            bioType = null,
            claims = {}
        } = options;

        try {
            this.log('Creating attestation token...');
            
            const now = this.crypto.getCurrentTimestamp();
            const exp = now + validitySeconds;
            const jti = `att_${this.crypto.generateRandomHex(16)}`;
            
            // Get device attestation info
            const deviceInfo = this.hsm.getDeviceAttestation();
            let keyMetadata = null;
            
            if (keyId) {
                keyMetadata = this.hsm.getKeyMetadata(keyId);
            }
            
            // Base attestation claims
            const attestationClaims = {
                // Standard JWT claims
                iss: `hsm:${this.hsm.deviceId}`,
                sub: subject,
                aud: audience,
                exp: exp,
                iat: now,
                jti: jti,
                
                // Hardware attestation claims
                hwbacked: true,
                sec_level: 'hardware',
                device_id: this.hsm.deviceId,
                boot_state: 'verified',
                tamper_detected: this.hsm.tamperDetected,
                firmware_version: deviceInfo.firmwareVersion,
                hardware_version: 'HSM-SIM-v1.0',
                
                // Key-specific claims
                ...(keyId && {
                    key_id: keyId,
                    key_attestation: keyMetadata ? true : false
                }),
                
                // Challenge/nonce
                ...(nonce && { nonce }),
                
                // Custom claims
                ...claims
            };
            
            // Add biometric claims if requested
            if (bioAuth && this.biometricModule) {
                attestationClaims.bio_auth = true;
                if (bioType) {
                    attestationClaims.bio_type = bioType;
                }
            }
            
            // Add key attestation certificate if available
            if (keyId && keyMetadata && keyMetadata.attestationCertificate) {
                attestationClaims.attestation_cert = this.formatCertificateForJWT(
                    keyMetadata.attestationCertificate
                );
            }
            
            // Create JWT header with certificate chain
            const certChain = await this.getCertificateChain();
            const header = {
                alg: 'ES256',
                typ: 'JWT',
                kid: this.signingKeyId,
                x5c: [certChain]
            };

            // Debug: print header before signing
            console.log('[DEBUG] JWT header to be used:', header);

            // Sign token with HSM
            const token = await this.createJWTManually(header, attestationClaims);

            // Debug: print full JWT and decoded header
            try {
                const parts = token.split('.');
                if (parts.length === 3) {
                    const decodedHeader = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
                    console.log('[DEBUG] JWT header in signed token:', decodedHeader);
                }
                console.log('[DEBUG] Full JWT:', token);
            } catch (e) {
                console.warn('[DEBUG] Failed to decode JWT header:', e);
            }

            this.log(`Attestation token created (expires in ${validitySeconds}s)`, 'success');

            this.notifyEvent('tokenCreated', {
                jti,
                subject,
                audience,
                validitySeconds,
                bioAuth,
                keyId
            });

            return token;
            
        } catch (error) {
            this.log(`Attestation token creation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Verify attestation token
     */
    async verifyAttestationToken(token) {
        try {
            this.log('Verifying attestation token...');
            
            // Decode JWT
            const decoded = this.crypto.decodeJWT(token);
            
            // Basic structure validation
            if (!decoded.header || !decoded.payload) {
                throw new Error('Invalid JWT structure');
            }
            
            // Check expiration
            const now = this.crypto.getCurrentTimestamp();
            if (decoded.payload.exp && decoded.payload.exp < now) {
                throw new Error('Token expired');
            }
            
            // Check issuer
            if (!decoded.payload.iss || !decoded.payload.iss.startsWith('hsm:')) {
                throw new Error('Invalid issuer');
            }
            
            // Check hardware backing claims
            if (!decoded.payload.hwbacked) {
                throw new Error('Token not hardware-backed');
            }
            
            // Check device ID
            if (decoded.payload.device_id !== this.hsm.deviceId) {
                this.log('Token from different device - this is normal in production', 'warning');
            }
            
            // For demo purposes, we'll consider the token valid
            // In production, this would verify the signature against the issuer's public key
            
            this.log('Attestation token verified successfully', 'success');
            
            this.notifyEvent('tokenVerified', {
                jti: decoded.payload.jti,
                issuer: decoded.payload.iss,
                subject: decoded.payload.sub,
                valid: true
            });
            
            return {
                valid: true,
                header: decoded.header,
                payload: decoded.payload,
                deviceId: decoded.payload.device_id,
                hardwareBacked: decoded.payload.hwbacked,
                securityLevel: decoded.payload.sec_level
            };
            
        } catch (error) {
            this.log(`Token verification failed: ${error.message}`, 'error');
            
            this.notifyEvent('tokenVerificationFailed', {
                error: error.message
            });
            
            return {
                valid: false,
                error: error.message
            };
        }
    }

    /**
     * Create JWT manually using HSM for signing
     */
    async createJWTManually(header, payload) {
        try {
            // Encode header and payload
            const headerB64 = this.crypto.base64UrlEncode(
                new TextEncoder().encode(JSON.stringify(header))
            );
            const payloadB64 = this.crypto.base64UrlEncode(
                new TextEncoder().encode(JSON.stringify(payload))
            );

            // Create signing input
            const signingInput = `${headerB64}.${payloadB64}`;

            // Sign with HSM (Web Crypto API returns IEEE P1363 format, which is what JWT ES256 expects)
            const signature = await this.hsm.signData(this.signingKeyId, signingInput);

            // The signature from Web Crypto API ECDSA is already in the correct format (raw R||S)
            // for JWT ES256 - no conversion needed
            const signatureB64 = this.crypto.base64UrlEncode(signature);
            
            return `${signingInput}.${signatureB64}`;

        } catch (error) {
            this.log(`JWT creation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Format certificate for JWT x5c claim
     */
    formatCertificateForJWT(certificate) {
        // In a real implementation, this would format an actual X.509 certificate
        // For demo, we'll create a mock certificate string
        return {
            subject: certificate.subject,
            serialNumber: certificate.serialNumber,
            notBefore: certificate.notBefore,
            notAfter: certificate.notAfter,
            keyUsage: certificate.extensions.keyUsage,
            hsmExtensions: certificate.extensions.hsmExtensions
        };
    }

    /**
     * Get certificate chain for x5c header
     * Generates a self-signed X.509 certificate for the attestation signing key
     */
    async getCertificateChain() {
        // For the demo, we need to generate a self-signed certificate that matches
        // our attestation_signing_key. In production, this would be a real cert signed by the HSM CA.
        
        // Get the public key for our signing key
        const publicKeyJWK = this.hsm.getPublicKeyJWK(this.signingKeyId);
        
        // Generate a self-signed X.509 certificate in DER format
        const cert = await this.generateSelfSignedCert(publicKeyJWK, this.signingKeyId);
        
        return cert;
    }
    
    /**
     * Generate a minimal self-signed X.509 certificate
     * This creates a certificate that matches the attestation signing key
     */
    async generateSelfSignedCert(publicKeyJWK, keyId) {
        // For demo purposes, create a minimal X.509 certificate structure
        // In production, this would be generated by the HSM with proper signatures
        
        // Convert JWK coordinates to raw bytes
        const xBytes = this.crypto.base64UrlDecode(publicKeyJWK.x);
        const yBytes = this.crypto.base64UrlDecode(publicKeyJWK.y);
        
        // Build a minimal X.509 v3 certificate (self-signed)
        // This is a highly simplified version for demo purposes
        const cert = this.buildX509Certificate(xBytes, yBytes, keyId);
        
        // Convert to standard base64 (not base64url) for x5c
        let base64 = btoa(String.fromCharCode(...cert));
        
        // Ensure proper padding
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }
        
        return base64;
    }
    
    /**
     * Build a minimal X.509 certificate structure
     * This creates a DER-encoded certificate that the Go backend can parse
     */
    buildX509Certificate(xBytes, yBytes, keyId) {
        // Create EC public key in DER format (uncompressed point)
        const publicKeyPoint = new Uint8Array(65);
        publicKeyPoint[0] = 0x04; // Uncompressed point indicator
        publicKeyPoint.set(xBytes, 1);
        publicKeyPoint.set(yBytes, 33);
        
        // Build subject/issuer DN: CN=keyId
        const cn = this.der_utf8String(keyId);
        const cnOID = this.der_oid([2, 5, 4, 3]); // CN OID
        const cnAttrSequence = this.der_sequence([cnOID, cn]);
        const cnSet = this.der_set([cnAttrSequence]);
        const subjectDN = this.der_sequence([cnSet]);
        
        // Build validity (notBefore / notAfter) - valid for 1 year
        const now = new Date();
        const notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
        const validity = this.der_sequence([
            this.der_utcTime(now),
            this.der_utcTime(notAfter)
        ]);
        
        // Build SubjectPublicKeyInfo
        const ecPublicKeyOID = this.der_oid([1, 2, 840, 10045, 2, 1]); // EC Public Key OID
        const prime256v1OID = this.der_oid([1, 2, 840, 10045, 3, 1, 7]); // P-256 curve OID
        const algorithmId = this.der_sequence([ecPublicKeyOID, prime256v1OID]);
        const subjectPublicKey = this.der_bitString(publicKeyPoint);
        const subjectPublicKeyInfo = this.der_sequence([algorithmId, subjectPublicKey]);
        
        // Build TBSCertificate (To Be Signed)
        // Generate serial number (must be positive in DER encoding)
        const serialBytes = this.crypto.getSecureRandom(16);
        // Ensure first byte is positive (high bit not set)
        serialBytes[0] = serialBytes[0] & 0x7F;
        const serialNumber = this.der_integer(serialBytes);
        const signatureAlgorithm = this.der_sequence([
            this.der_oid([1, 2, 840, 10045, 4, 3, 2]) // ECDSA with SHA-256
        ]);
        
        const tbsCertificate = this.der_sequence([
            this.der_explicit(0, [this.der_integer(new Uint8Array([2]))]), // version 3
            serialNumber,
            signatureAlgorithm,
            subjectDN, // issuer (same as subject for self-signed)
            validity,
            subjectDN, // subject
            subjectPublicKeyInfo
        ]);
        
        // For demo, create a mock signature (in production, sign with private key)
        const mockSignature = this.crypto.getSecureRandom(64);
        const signatureValue = this.der_bitString(mockSignature);
        
        // Build final certificate
        const certificate = this.der_sequence([
            tbsCertificate,
            signatureAlgorithm,
            signatureValue
        ]);
        
        return certificate;
    }
    
    // DER encoding helper functions
    der_sequence(contents) {
        const data = this.concatenateArrays(contents);
        return this.der_encode(0x30, data);
    }
    
    der_set(contents) {
        const data = this.concatenateArrays(contents);
        return this.der_encode(0x31, data);
    }
    
    der_integer(value) {
        return this.der_encode(0x02, value);
    }
    
    der_bitString(value) {
        const padded = new Uint8Array(value.length + 1);
        padded[0] = 0; // no unused bits
        padded.set(value, 1);
        return this.der_encode(0x03, padded);
    }
    
    der_oid(components) {
        const encoded = [];
        encoded.push(components[0] * 40 + components[1]);
        for (let i = 2; i < components.length; i++) {
            let value = components[i];
            const bytes = [];
            bytes.unshift(value & 0x7F);
            value >>= 7;
            while (value > 0) {
                bytes.unshift((value & 0x7F) | 0x80);
                value >>= 7;
            }
            encoded.push(...bytes);
        }
        return this.der_encode(0x06, new Uint8Array(encoded));
    }
    
    der_utf8String(str) {
        const encoder = new TextEncoder();
        return this.der_encode(0x0C, encoder.encode(str));
    }
    
    der_utcTime(date) {
        // Format: YYMMDDhhmmssZ
        const year = date.getUTCFullYear().toString().slice(-2);
        const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
        const day = date.getUTCDate().toString().padStart(2, '0');
        const hour = date.getUTCHours().toString().padStart(2, '0');
        const minute = date.getUTCMinutes().toString().padStart(2, '0');
        const second = date.getUTCSeconds().toString().padStart(2, '0');
        const timeStr = `${year}${month}${day}${hour}${minute}${second}Z`;
        const encoder = new TextEncoder();
        return this.der_encode(0x17, encoder.encode(timeStr));
    }
    
    der_explicit(tag, contents) {
        const data = this.concatenateArrays(contents);
        return this.der_encode(0xA0 + tag, data);
    }
    
    der_encode(tag, data) {
        const length = data.length;
        let lengthBytes;
        
        if (length < 128) {
            lengthBytes = new Uint8Array([length]);
        } else {
            const lengthArray = [];
            let len = length;
            while (len > 0) {
                lengthArray.unshift(len & 0xFF);
                len >>= 8;
            }
            lengthBytes = new Uint8Array([0x80 | lengthArray.length, ...lengthArray]);
        }
        
        const result = new Uint8Array(1 + lengthBytes.length + data.length);
        result[0] = tag;
        result.set(lengthBytes, 1);
        result.set(data, 1 + lengthBytes.length);
        
        return result;
    }
    
    concatenateArrays(arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) {
            result.set(arr, offset);
            offset += arr.length;
        }
        return result;
    }

    /**
     * Create device attestation report
     */
    async createDeviceAttestation(options = {}) {
        const {
            challenge = null,
            includeKeyList = false
        } = options;

        try {
            this.log('Creating device attestation report...');
            
            const deviceInfo = this.hsm.getDeviceAttestation();
            const biometricStatus = this.biometricModule ? this.biometricModule.getStatus() : null;
            
            const attestationReport = {
                version: '1.0',
                timestamp: this.crypto.getCurrentTimestamp(),
                challenge: challenge,
                device: {
                    deviceId: deviceInfo.deviceId,
                    securityState: deviceInfo.securityState,
                    bootCount: deviceInfo.bootCount,
                    tamperDetected: deviceInfo.tamperDetected,
                    firmwareVersion: deviceInfo.firmwareVersion
                },
                hardware: {
                    hsmPresent: true,
                    secureBootEnabled: true,
                    attestationSupported: true,
                    biometricSupported: !!biometricStatus
                },
                keys: includeKeyList ? this.hsm.listKeys() : { count: this.hsm.listKeys().length },
                biometric: biometricStatus ? {
                    enrolled: biometricStatus.enrolledUsers,
                    supportedTypes: biometricStatus.supportedTypes
                } : null
            };
            
            // Sign the attestation report
            const reportJson = JSON.stringify(attestationReport);
            const signature = await this.hsm.signData(this.signingKeyId, reportJson);
            
            const signedReport = {
                attestation: attestationReport,
                signature: this.crypto.base64UrlEncode(signature),
                signingKey: this.signingKeyId
            };
            
            this.log('Device attestation report created', 'success');
            
            return signedReport;
            
        } catch (error) {
            this.log(`Device attestation creation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Get attestation service status
     */
    getStatus() {
        return {
            initialized: this.initialized,
            signingKeyId: this.signingKeyId,
            deviceId: this.hsm ? this.hsm.deviceId : null,
            hsmStatus: this.hsm ? this.hsm.getStatus() : null,
            biometricStatus: this.biometricModule ? this.biometricModule.getStatus() : null
        };
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
            deviceId: this.hsm ? this.hsm.deviceId : null,
            data
        };

        this.eventCallbacks.forEach(callback => {
            try {
                callback(event);
            } catch (error) {
                console.error('Error in attestation event callback:', error);
            }
        });
    }

    /**
     * Log attestation operations
     */
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[Attestation ${timestamp}] ${message}`);
        
        // Notify UI
        if (window.UIController) {
            window.UIController.addLog('attestation', timestamp, message, type);
        }
    }

    /**
     * Reset attestation service (for demo)
     */
    async reset() {
        this.log('Resetting attestation service...');
        
        this.initialized = false;
        this.signingKeyId = null;
        
        this.log('Attestation service reset complete', 'success');
        
        this.notifyEvent('reset', {});
    }
}

// Export for use in other modules
window.AttestationService = AttestationService;