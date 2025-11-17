/**
 * Biometric Authentication Simulator
 * 
 * Simulates biometric authentication including fingerprint enrollment,
 * authentication, and hardware-backed biometric verification.
 */

class BiometricSimulator {
    constructor(hsm) {
        this.hsm = hsm;
        this.crypto = new CryptoUtils();
        this.enrolledTemplates = new Map(); // userId -> template data
        this.biometricKeyId = null;
        this.initialized = false;
        
        this.eventCallbacks = [];
    }

    /**
     * Initialize biometric module
     */
    async initialize() {
        console.log('DEBUG: Biometric initialize called');
        console.log('DEBUG: this.hsm exists?', !!this.hsm);
        console.log('DEBUG: this.hsm.initialized?', this.hsm ? this.hsm.initialized : 'N/A');
        console.log('DEBUG: HSM object:', this.hsm);
        
        if (!this.hsm || !this.hsm.initialized) {
            const error = new Error('HSM must be initialized before biometric module');
            console.log('DEBUG: Throwing HSM dependency error');
            throw error;
        }

        try {
            this.log('Initializing biometric module...');
            
            // Check if we already have a biometric key
            if (this.biometricKeyId && this.hsm.keys && this.hsm.keys.has(this.biometricKeyId)) {
                console.log(`DEBUG: Biometric key ${this.biometricKeyId} already exists, skipping generation`);
                this.initialized = true;
                this.log('Biometric module already initialized', 'success');
                return {
                    initialized: true,
                    biometricKeyId: this.biometricKeyId
                };
            }
            
            // Generate biometric authentication key in HSM
            console.log('DEBUG: Generating biometric authentication key...');
            this.biometricKeyId = await this.hsm.generateKeyPair('biometric_auth_key', 'EC-P256');
            console.log('DEBUG: Generated biometric key:', this.biometricKeyId);
            
            // Verify the key was actually created
            if (!this.hsm.keys || !this.hsm.keys.has(this.biometricKeyId)) {
                throw new Error('Biometric key was not properly stored in HSM');
            }
            
            console.log('DEBUG: Biometric key verified in HSM');
            
            this.initialized = true;
            
            this.log('Biometric module initialized successfully', 'success');
            this.log(`Biometric key: ${this.biometricKeyId}`, 'info');
            
            this.notifyEvent('initialized', {
                biometricKeyId: this.biometricKeyId
            });
            
            return {
                initialized: true,
                biometricKeyId: this.biometricKeyId
            };
            
        } catch (error) {
            console.error('DEBUG: Biometric initialization failed:', error);
            this.log(`Biometric initialization failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Enroll user biometric template
     */
    async enrollBiometric(userId, biometricType = 'fingerprint') {
        if (!this.initialized) {
            throw new Error('Biometric module not initialized');
        }

        try {
            this.log(`Enrolling ${biometricType} for user: ${userId}`);
            
            // Simulate biometric capture and template creation
            const templateId = `bio_${this.crypto.generateRandomHex(8)}`;
            
            // Create mock template data (in reality, this would be actual biometric data)
            const mockBiometricData = `${userId}_${biometricType}_${Date.now()}`;
            const templateHash = await this.crypto.sha256(mockBiometricData);
            
            const template = {
                templateId,
                userId,
                biometricType,
                templateHash: this.crypto.arrayBufferToHex(templateHash),
                createdAt: Date.now(),
                qualityScore: 0.95, // High quality for simulation
                deviceId: this.hsm.deviceId,
                version: '1.0'
            };
            
            this.enrolledTemplates.set(userId, template);
            
            this.log(`Biometric enrolled successfully: ${templateId}`, 'success');
            this.log(`Quality score: ${(template.qualityScore * 100).toFixed(1)}%`, 'info');
            
            this.notifyEvent('enrolled', {
                userId,
                templateId,
                biometricType,
                qualityScore: template.qualityScore
            });
            
            return templateId;
            
        } catch (error) {
            this.log(`Biometric enrollment failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Authenticate user with biometric
     */
    async authenticateBiometric(userId, challenge = null) {
        if (!this.initialized) {
            console.error('Biometric authenticate called but module not initialized');
            return {
                success: false,
                error: 'Biometric module not initialized'
            };
        }

        if (!this.enrolledTemplates.has(userId)) {
            console.error(`Biometric authenticate called but no template for user: ${userId}`);
            this.log(`No biometric template for user: ${userId}`, 'error');
            return {
                success: false,
                error: 'No biometric template enrolled for user'
            };
        }

        // Check if biometric key exists
        if (!this.biometricKeyId) {
            console.error('Biometric authenticate called but no biometric key available');
            return {
                success: false,
                error: 'Biometric authentication key not available'
            };
        }

        // Verify the key still exists in HSM
        try {
            if (!this.hsm || !this.hsm.keys || !this.hsm.keys.has(this.biometricKeyId)) {
                console.error(`Biometric key ${this.biometricKeyId} not found in HSM`);
                return {
                    success: false,
                    error: 'Biometric authentication key lost from HSM'
                };
            }
        } catch (error) {
            console.error('Error checking biometric key in HSM:', error);
            return {
                success: false,
                error: 'Error verifying biometric key'
            };
        }

        try {
            this.log(`Authenticating ${userId} with biometric...`);
            
            const template = this.enrolledTemplates.get(userId);
            
            // Simulate biometric verification (always succeeds for demo, but with realistic delay)
            await this.simulateBiometricScan();
            
            const authSuccess = true; // In reality, this would be actual biometric matching
            const confidenceScore = 0.98; // High confidence for demo
            
            if (authSuccess) {
                // Create authentication proof signed by HSM
                const authData = {
                    userId,
                    templateId: template.templateId,
                    biometricType: template.biometricType,
                    timestamp: this.crypto.getCurrentTimestamp(),
                    challenge: challenge,
                    confidenceScore,
                    deviceId: this.hsm.deviceId,
                    nonce: this.crypto.generateNonce()
                };
                
                // Sign authentication proof with HSM
                const authJson = JSON.stringify(authData);
                console.log(`Attempting to sign with biometric key: ${this.biometricKeyId}`);
                const signature = await this.hsm.signData(this.biometricKeyId, authJson);
                const authProof = this.crypto.base64UrlEncode(signature);
                
                this.log(`Biometric authentication successful`, 'success');
                this.log(`Confidence score: ${(confidenceScore * 100).toFixed(1)}%`, 'info');
                
                this.notifyEvent('authenticated', {
                    userId,
                    biometricType: template.biometricType,
                    confidenceScore,
                    success: true
                });
                
                return {
                    success: true,
                    userId,
                    biometricType: template.biometricType,
                    templateId: template.templateId,
                    confidenceScore,
                    authProof,
                    authData,
                    timestamp: authData.timestamp
                };
                
            } else {
                this.log(`Biometric authentication failed`, 'error');
                
                this.notifyEvent('authenticationFailed', {
                    userId,
                    biometricType: template.biometricType,
                    reason: 'Biometric verification failed'
                });
                
                return {
                    success: false,
                    error: 'Biometric verification failed'
                };
            }
            
        } catch (error) {
            console.error('Biometric authentication error:', error);
            this.log(`Biometric authentication error: ${error.message}`, 'error');
            
            this.notifyEvent('authenticationError', {
                userId,
                error: error.message
            });
            
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Simulate biometric scanning process
     */
    async simulateBiometricScan() {
        return new Promise((resolve) => {
            this.log('Please place finger on scanner...', 'info');
            
            setTimeout(() => {
                this.log('Scanning biometric...', 'info');
                
                setTimeout(() => {
                    this.log('Biometric scan complete', 'success');
                    resolve();
                }, 1000);
            }, 500);
        });
    }

    /**
     * Get enrolled biometric information
     */
    getEnrolledBiometric(userId) {
        if (!this.enrolledTemplates.has(userId)) {
            return null;
        }
        
        const template = this.enrolledTemplates.get(userId);
        
        // Return safe information (no template hash)
        return {
            templateId: template.templateId,
            userId: template.userId,
            biometricType: template.biometricType,
            createdAt: template.createdAt,
            qualityScore: template.qualityScore,
            deviceId: template.deviceId
        };
    }

    /**
     * List all enrolled users
     */
    getEnrolledUsers() {
        const users = [];
        for (const [userId, template] of this.enrolledTemplates.entries()) {
            users.push({
                userId,
                templateId: template.templateId,
                biometricType: template.biometricType,
                createdAt: template.createdAt,
                qualityScore: template.qualityScore
            });
        }
        return users;
    }

    /**
     * Remove biometric enrollment
     */
    removeBiometric(userId) {
        if (this.enrolledTemplates.has(userId)) {
            const template = this.enrolledTemplates.get(userId);
            this.enrolledTemplates.delete(userId);
            
            this.log(`Biometric enrollment removed for: ${userId}`, 'info');
            
            this.notifyEvent('enrollmentRemoved', {
                userId,
                templateId: template.templateId
            });
            
            return true;
        }
        return false;
    }

    /**
     * Generate biometric challenge
     */
    generateChallenge() {
        return this.crypto.generateNonce(32);
    }

    /**
     * Verify biometric proof
     */
    async verifyBiometricProof(userId, authProof, authData) {
        try {
            if (!this.enrolledTemplates.has(userId)) {
                return false;
            }
            
            // Verify signature with HSM
            const authJson = JSON.stringify(authData);
            const signature = this.crypto.base64UrlDecode(authProof);
            const publicKey = this.hsm.getPublicKeyJWK(this.biometricKeyId);
            
            // For demo purposes, we'll assume verification succeeds
            // In reality, this would use the actual public key and crypto.subtle.verify
            
            this.log(`Biometric proof verified for: ${userId}`, 'success');
            return true;
            
        } catch (error) {
            this.log(`Biometric proof verification failed: ${error.message}`, 'error');
            return false;
        }
    }

    /**
     * Get biometric module status
     */
    getStatus() {
        return {
            initialized: this.initialized,
            biometricKeyId: this.biometricKeyId,
            enrolledUsers: this.enrolledTemplates.size,
            supportedTypes: ['fingerprint'], // Could expand to face, voice, etc.
            deviceId: this.hsm ? this.hsm.deviceId : null
        };
    }

    /**
     * Simulate different biometric scenarios
     */
    async simulateScenario(scenario, userId) {
        switch (scenario) {
            case 'failed_scan':
                this.log(`Simulating failed biometric scan for: ${userId}`, 'warning');
                return {
                    success: false,
                    error: 'Biometric scan failed - please try again'
                };
                
            case 'low_quality':
                this.log(`Simulating low quality biometric for: ${userId}`, 'warning');
                await this.simulateBiometricScan();
                return {
                    success: false,
                    error: 'Low quality biometric - please clean sensor and try again'
                };
                
            case 'multiple_attempts':
                this.log(`Simulating multiple authentication attempts for: ${userId}`, 'info');
                for (let i = 1; i <= 3; i++) {
                    this.log(`Authentication attempt ${i}/3...`, 'info');
                    await this.simulateBiometricScan();
                }
                return await this.authenticateBiometric(userId);
                
            default:
                return await this.authenticateBiometric(userId);
        }
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
                console.error('Error in biometric event callback:', error);
            }
        });
    }

    /**
     * Log biometric operations
     */
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[Biometric ${timestamp}] ${message}`);
        
        // Notify UI
        if (window.UIController) {
            window.UIController.addLog('bio', timestamp, message, type);
        }
    }

    /**
     * Reset biometric module (for demo)
     */
    async reset() {
        this.log('Resetting biometric module...');
        
        this.enrolledTemplates.clear();
        this.initialized = false;
        this.biometricKeyId = null;
        
        // Don't auto-reinitialize here - let the main initialization flow handle it
        // This prevents issues if HSM is reset after biometric
        
        this.log('Biometric module reset complete', 'success');
        
        this.notifyEvent('reset', {});
    }
}

// Export for use in other modules  
window.BiometricSimulator = BiometricSimulator;