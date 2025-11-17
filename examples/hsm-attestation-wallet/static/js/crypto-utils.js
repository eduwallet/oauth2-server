/**
 * Crypto Utilities for Browser-based HSM Simulation
 * 
 * This module provides cryptographic functions that simulate
 * hardware security module operations in the browser.
 */

class CryptoUtils {
    constructor() {
        this.subtle = window.crypto.subtle;
    }

    /**
     * Generate a random UUID
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    /**
     * Generate a random hex string
     */
    generateRandomHex(length) {
        const array = new Uint8Array(length / 2);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Generate a random string for OAuth2 state/nonce/code_verifier
     */
    generateRandomString(length = 32) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => characters[byte % characters.length]).join('');
    }

    /**
     * Create PKCE code challenge from code verifier
     */
    async createCodeChallenge(codeVerifier) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(codeVerifier);
            const digest = await this.subtle.digest('SHA-256', data);
            return this.base64UrlEncode(digest);
        } catch (error) {
            console.error('Error creating code challenge:', error);
            throw error;
        }
    }

    /**
     * Generate ECDSA key pair (P-256)
     */
    async generateECKeyPair() {
        try {
            const keyPair = await this.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true, // extractable
                ["sign", "verify"]
            );
            
            return keyPair;
        } catch (error) {
            console.error('Error generating EC key pair:', error);
            throw error;
        }
    }

    /**
     * Sign data with ECDSA private key
     */
    async signData(privateKey, data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
            
            const signature = await this.subtle.sign(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                privateKey,
                dataBuffer
            );
            
            return new Uint8Array(signature);
        } catch (error) {
            console.error('Error signing data:', error);
            throw error;
        }
    }

    /**
     * Verify signature with ECDSA public key
     */
    async verifySignature(publicKey, signature, data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
            
            const isValid = await this.subtle.verify(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                publicKey,
                signature,
                dataBuffer
            );
            
            return isValid;
        } catch (error) {
            console.error('Error verifying signature:', error);
            return false;
        }
    }

    /**
     * Export public key to JWK format
     */
    async exportPublicKeyJWK(publicKey) {
        try {
            const jwk = await this.subtle.exportKey('jwk', publicKey);
            return jwk;
        } catch (error) {
            console.error('Error exporting public key:', error);
            throw error;
        }
    }

    /**
     * Export private key to JWK format
     */
    async exportPrivateKeyJWK(privateKey) {
        try {
            const jwk = await this.subtle.exportKey('jwk', privateKey);
            return jwk;
        } catch (error) {
            console.error('Error exporting private key:', error);
            throw error;
        }
    }

    /**
     * Import public key from JWK format
     */
    async importPublicKeyJWK(jwk) {
        try {
            const key = await this.subtle.importKey(
                'jwk',
                jwk,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ['verify']
            );
            return key;
        } catch (error) {
            console.error('Error importing public key:', error);
            throw error;
        }
    }

    /**
     * Create SHA-256 hash
     */
    async sha256(data) {
        const encoder = new TextEncoder();
        const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
        const hashBuffer = await this.subtle.digest('SHA-256', dataBuffer);
        return new Uint8Array(hashBuffer);
    }

    /**
     * Base64 URL encode
     */
    base64UrlEncode(buffer) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    /**
     * Base64 URL decode
     */
    base64UrlDecode(str) {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) {
            str += '=';
        }
        const binary = atob(str);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    /**
     * Generate key thumbprint (JWK thumbprint)
     */
    async generateKeyThumbprint(publicKeyJWK) {
        try {
            // Create canonical JWK for thumbprint
            const canonicalJWK = {
                crv: publicKeyJWK.crv,
                kty: publicKeyJWK.kty,
                x: publicKeyJWK.x,
                y: publicKeyJWK.y
            };
            
            const jwkString = JSON.stringify(canonicalJWK);
            const hash = await this.sha256(jwkString);
            return this.base64UrlEncode(hash);
        } catch (error) {
            console.error('Error generating key thumbprint:', error);
            throw error;
        }
    }

    /**
     * Create JWT manually (for demonstration purposes)
     */
    async createJWT(header, payload, privateKey) {
        try {
            // Encode header and payload
            const headerB64 = this.base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
            const payloadB64 = this.base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
            
            // Create signing input
            const signingInput = `${headerB64}.${payloadB64}`;
            
            // Sign
            const signature = await this.signData(privateKey, signingInput);
            const signatureB64 = this.base64UrlEncode(signature);
            
            return `${signingInput}.${signatureB64}`;
        } catch (error) {
            console.error('Error creating JWT:', error);
            throw error;
        }
    }

    /**
     * Decode JWT (without verification)
     */
    decodeJWT(jwt) {
        try {
            const parts = jwt.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format');
            }

            const header = JSON.parse(new TextDecoder().decode(this.base64UrlDecode(parts[0])));
            const payload = JSON.parse(new TextDecoder().decode(this.base64UrlDecode(parts[1])));
            const signature = parts[2];

            return { header, payload, signature };
        } catch (error) {
            console.error('Error decoding JWT:', error);
            throw error;
        }
    }

    /**
     * Generate secure random nonce
     */
    generateNonce(length = 32) {
        return this.generateRandomHex(length);
    }

    /**
     * Current timestamp in seconds
     */
    getCurrentTimestamp() {
        return Math.floor(Date.now() / 1000);
    }

    /**
     * Format timestamp for display
     */
    formatTimestamp(timestamp) {
        return new Date(timestamp * 1000).toISOString();
    }

    /**
     * Simulate secure random bytes
     */
    getSecureRandom(length) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return array;
    }

    /**
     * Convert ArrayBuffer to hex string
     */
    arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex string to ArrayBuffer
     */
    hexToArrayBuffer(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes.buffer;
    }
}

// Export for use in other modules
window.CryptoUtils = CryptoUtils;