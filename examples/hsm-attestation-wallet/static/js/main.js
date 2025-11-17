/**
 * HSM Attestation Wallet Demo - Main Application
 * 
 * Demonstrates hardware-backed JWT attestation authentication
 * with OAuth2 integration, biometric authentication.
 */

class HSMAttestationWalletDemo {
    constructor() {
        this.initialized = false;
        this.services = {};
        
        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }
    }

    /**
     * Initialize the complete demo application
     */
    async initialize() {
        try {
            console.log('🚀 Starting HSM Attestation Wallet Demo...');
            
            // Check if we're returning from OAuth callback
            if (this.isOAuthCallback()) {
                console.log('📥 Detected OAuth callback - restoring state...');
                await this.handleOAuthCallback();
                return;
            }
            
            // Check if we should restore previous state
            if (this.shouldRestoreState()) {
                console.log('🔄 Restoring previous application state...');
                await this.restoreApplicationState();
                return;
            }
            
            // Show loading state
            this.showLoadingState();
            
            // Initialize services in correct order
            try {
                console.log('🔧 Starting service initialization...');
                await this.initializeServices();
                console.log('✅ Service initialization completed');
            } catch (error) {
                console.error('❌ Service initialization failed:', error);
                throw error;
            }
            
            // Setup UI
            try {
                console.log('🖥️ Starting UI initialization...');
                await this.initializeUI();
                console.log('✅ UI initialization completed');
            } catch (error) {
                console.error('❌ UI initialization failed:', error);
                throw error;
            }
            
            // Setup demo scenarios
            this.setupDemoScenarios();
            
            this.initialized = true;
            
            // Check for OAuth2 callback AFTER services are initialized
            await this.checkForOAuth2Callback();
            
            console.log('✅ HSM Attestation Wallet Demo initialized successfully');
            
            // Hide loading state
            this.hideLoadingState();
            
            // Show welcome message
            this.showWelcomeMessage();
            
        } catch (error) {
            console.error('❌ Demo initialization failed:', error);
            this.showInitializationError(error);
        }
    }

    /**
     * Initialize all security services
     */
    async initializeServices() {
        console.log('Initializing security services...');
        
        // Initialize HSM simulator
        this.services.hsm = new HSMSimulator();
        console.log('✓ HSM Simulator created');
        console.log('DEBUG: HSM object after creation:', this.services.hsm);
        
        // Initialize biometric module (pass HSM reference)
        this.services.biometric = new BiometricSimulator(this.services.hsm);
        console.log('✓ Biometric Simulator created');
        console.log('DEBUG: Biometric HSM reference:', this.services.biometric.hsm);
        console.log('DEBUG: HSM and Biometric HSM are same object?', this.services.hsm === this.services.biometric.hsm);
        
        // Initialize attestation service
        this.services.attestation = new AttestationService(
            this.services.hsm,
            this.services.biometric
        );
        console.log('✓ Attestation Service created');
        
        // Initialize OAuth2 client
        const serverUrl = window.HSM_DEMO_CONFIG?.serverUrl || 'http://localhost:8080';
        this.services.oauth2 = new OAuth2Client(this.services.attestation, {
            serverUrl,
            clientId: 'hsm-attestation-wallet-demo',
            redirectUri: `${window.location.origin}/callback.html`,
            scope: 'openid profile email'
        });
        console.log('✓ OAuth2 Client created');
        
        console.log('All services created successfully');
        
        // Initialize the services
        console.log('Initializing HSM...');
        await this.services.hsm.initialize();
        console.log('✓ HSM initialized');
        
        console.log('Initializing biometric simulator...');
        await this.services.biometric.initialize();
        console.log('✓ Biometric simulator initialized');
        
        console.log('Initializing attestation service...');
        await this.services.attestation.initialize();
        console.log('✓ Attestation service initialized');
        
        console.log('Initializing OAuth2 client...');
        await this.services.oauth2.initialize();
        console.log('✓ OAuth2 client initialized');
        
        console.log('All services initialized successfully');
    }

    /**
     * Initialize user interface
     */
    async initializeUI() {
        console.log('Initializing user interface...');
        
        // Wait for UI Controller to be ready
        if (!window.UIController || !window.UIController.initialized) {
            console.log('Waiting for UI Controller to be ready...');
            await new Promise(resolve => {
                const checkAndResolve = () => {
                    if (window.UIController && window.UIController.initialized) {
                        resolve();
                    }
                };
                
                // Check immediately
                checkAndResolve();
                
                // Listen for ready event
                window.addEventListener('uiControllerReady', checkAndResolve, { once: true });
                
                // Fallback timeout after 5 seconds
                setTimeout(() => {
                    console.warn('UI Controller ready timeout, proceeding anyway');
                    resolve();
                }, 5000);
            });
        }
        
        if (!window.UIController) {
            console.error('❌ UI Controller not available after waiting');
            throw new Error('UI Controller not available');
        }
        
        // Register services with UI controller
        console.log('UI Controller found, registering services...');
        console.log('DEBUG: Services to register:', this.services);
        console.log('DEBUG: window.UIController:', window.UIController);
        console.log('DEBUG: window.UIController.initialized:', window.UIController.initialized);
        
        window.UIController.registerServices(this.services);
        console.log('✓ Services registered with UI Controller');
        
        // Verify registration worked
        console.log('DEBUG: UIController.services after registration:', window.UIController.services);
        
        // Setup global error handling
        this.setupErrorHandling();
        
        console.log('User interface initialized successfully');
    }

    /**
     * Check if we're on an OAuth2 callback URL and handle it
     */
    async checkForOAuth2Callback() {
        try {
            // Check URL parameters first
            const urlParams = new URLSearchParams(window.location.search);
            let code = urlParams.get('code');
            let state = urlParams.get('state');
            const error = urlParams.get('error');
            
            // If not in URL, check sessionStorage (from callback.html redirect)
            if (!code && !error) {
                code = sessionStorage.getItem('oauth_callback_code');
                state = sessionStorage.getItem('oauth_callback_state');
                
                // Clear sessionStorage after reading
                if (code && state) {
                    sessionStorage.removeItem('oauth_callback_code');
                    sessionStorage.removeItem('oauth_callback_state');
                }
            }
            
            if (error) {
                console.error('OAuth2 error:', error);
                if (window.UIController) {
                    window.UIController.showError(`OAuth2 authorization failed: ${error}`);
                }
                // Clean the URL
                window.history.replaceState({}, document.title, window.location.pathname);
                return;
            }
            
            if (code && state) {
                console.log('OAuth2 callback detected, handling authorization code...');
                
                if (window.UIController) {
                    window.UIController.showInfo('Processing OAuth2 authorization...');
                }
                
                // Switch to OAuth2 tab to show the process
                const oauth2Tab = document.querySelector('[data-view="oauth2"]');
                if (oauth2Tab) {
                    oauth2Tab.click();
                }
                
                try {
                    // Ensure OAuth2 service is initialized before handling callback
                    if (!this.services.oauth2.getStatus().initialized) {
                        console.log('Initializing OAuth2 service for callback handling...');
                        await this.services.oauth2.initialize();
                    }
                    
                    // Handle the callback
                    const tokens = await this.services.oauth2.handleAuthorizationCallback(code, state);
                    
                    console.log('OAuth2 authorization successful:', tokens);
                    
                    if (window.UIController) {
                        window.UIController.showSuccess('OAuth2 authorization completed successfully!');
                        window.UIController.updateOAuthResult(tokens);
                    }
                    
                } catch (error) {
                    console.error('OAuth2 callback handling failed:', error);
                    
                    if (window.UIController) {
                        window.UIController.showError(`OAuth2 callback failed: ${error.message}`);
                    }
                }
                
                // Clean the URL
                window.history.replaceState({}, document.title, window.location.pathname);
            }
            
        } catch (error) {
            console.error('Error checking for OAuth2 callback:', error);
        }
    }

    /**
     * Setup demo scenarios
     */
    setupDemoScenarios() {
        console.log('Setting up demo scenarios...');
        
        // Add demo data and scenarios
        this.demoScenarios = {
            quickStart: this.createQuickStartScenario(),
            fullFlow: this.createFullFlowScenario(),
            securityDemo: this.createSecurityDemoScenario()
        };
        
        // Add keyboard shortcuts for demo
        this.setupKeyboardShortcuts();
        
        console.log('Demo scenarios configured');
    }

    /**
     * Create quick start demo scenario
     */
    createQuickStartScenario() {
        return {
            name: 'Quick Start Demo',
            description: 'Initialize all services',
            steps: [
                {
                    name: 'Initialize HSM',
                    action: () => this.services.hsm.initialize(),
                    description: 'Initialize Hardware Security Module simulator'
                },
                {
                    name: 'Initialize Biometric',
                    action: () => this.services.biometric.initialize(),
                    description: 'Initialize biometric authentication system'
                },
                {
                    name: 'Enroll User',
                    action: () => this.services.biometric.enrollUser('demouser', 'fingerprint'),
                    description: 'Enroll demo user for biometric authentication'
                },
                {
                    name: 'Initialize Attestation',
                    action: () => this.services.attestation.initialize(),
                    description: 'Initialize JWT attestation service'
                },
                {
                    name: 'Initialize OAuth2',
                    action: () => this.services.oauth2.initialize(),
                    description: 'Initialize OAuth2 client with attestation'
                }
            ]
        };
    }

    /**
     * Create full flow demo scenario
     */
    createFullFlowScenario() {
        return {
            name: 'Complete Authentication Flow',
            description: 'Demonstrate complete OAuth2 flow with attestation',
            steps: [
                {
                    name: 'Initialize All Services',
                    action: async () => {
                        await this.services.hsm.initialize();
                        await this.services.biometric.initialize();
                        await this.services.attestation.initialize();
                        await this.services.oauth2.initialize();
                    },
                    description: 'Initialize all security services'
                },
                {
                    name: 'Biometric Enrollment',
                    action: () => this.services.biometric.enrollUser('demouser', 'fingerprint'),
                    description: 'Enroll user for biometric authentication'
                },
                {
                    name: 'Create Attestation Token',
                    action: () => this.services.attestation.createAttestationToken({
                        subject: 'demo-user',
                        audience: 'oauth2-server',
                        bioAuth: true,
                        bioType: 'fingerprint'
                    }),
                    description: 'Create hardware-backed attestation token'
                },
                {
                    name: 'Register OAuth2 Client',
                    action: () => this.services.oauth2.registerClient(),
                    description: 'Register OAuth2 client with attestation'
                },
                {
                    name: 'Start OAuth2 Flow',
                    action: () => this.services.oauth2.startAuthorizationCodeFlow(),
                    description: 'Initiate OAuth2 authorization code flow'
                }
            ]
        };
    }

    /**
     * Create security demo scenario
     */
    createSecurityDemoScenario() {
        return {
            name: 'Security Features Demo',
            description: 'Demonstrate all security features',
            steps: [
                {
                    name: 'HSM Key Generation',
                    action: async () => {
                        await this.services.hsm.initialize();
                        return this.services.hsm.generateKeyPair('demo_key', 'EC-P256');
                    },
                    description: 'Generate key pair in HSM'
                },
                {
                    name: 'Key Attestation',
                    action: () => this.services.hsm.generateKeyAttestation('demo_key'),
                    description: 'Generate attestation certificate for key'
                },
                {
                    name: 'Biometric Authentication',
                    action: async () => {
                        await this.services.biometric.initialize();
                        await this.services.biometric.enrollUser('demouser', 'face');
                        return this.services.biometric.authenticate('demouser', 'face');
                    },
                    description: 'Demonstrate biometric authentication'
                },
                {
                    name: 'Attestation Token',
                    action: async () => {
                        await this.services.attestation.initialize();
                        return this.services.attestation.createAttestationToken({
                            subject: 'security-demo',
                            audience: 'demo-app',
                            keyId: 'demo_key',
                            bioAuth: true,
                            bioType: 'face'
                        });
                    },
                    description: 'Create comprehensive attestation token'
                }
            ]
        };
    }

    /**
     * Run a demo scenario
     */
    async runScenario(scenarioName) {
        const scenario = this.demoScenarios[scenarioName];
        if (!scenario) {
            throw new Error(`Unknown scenario: ${scenarioName}`);
        }
        
        console.log(`🎬 Running scenario: ${scenario.name}`);
        
        if (window.UIController) {
            window.UIController.showInfo(`Starting scenario: ${scenario.name}`);
        }
        
        try {
            for (let i = 0; i < scenario.steps.length; i++) {
                const step = scenario.steps[i];
                
                console.log(`Step ${i + 1}/${scenario.steps.length}: ${step.name}`);
                
                if (window.UIController) {
                    window.UIController.showInfo(`Step ${i + 1}: ${step.description}`);
                }
                
                const result = await step.action();
                
                // Brief pause between steps for demo effect
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
            
            console.log(`✅ Scenario completed: ${scenario.name}`);
            
            if (window.UIController) {
                window.UIController.showSuccess(`Scenario completed: ${scenario.name}`);
            }
            
        } catch (error) {
            console.error(`❌ Scenario failed: ${scenario.name}`, error);
            
            if (window.UIController) {
                window.UIController.showError(`Scenario failed: ${error.message}`);
            }
            
            throw error;
        }
    }

    /**
     * Setup keyboard shortcuts
     */
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (event) => {
            // Only trigger if not in an input field
            if (event.target.tagName.toLowerCase() === 'input') return;
            
            switch (event.key) {
                case '1':
                    if (event.ctrlKey || event.metaKey) {
                        event.preventDefault();
                        this.runScenario('quickStart');
                    }
                    break;
                case '2':
                    if (event.ctrlKey || event.metaKey) {
                        event.preventDefault();
                        this.runScenario('fullFlow');
                    }
                    break;
                case '3':
                    if (event.ctrlKey || event.metaKey) {
                        event.preventDefault();
                        this.runScenario('securityDemo');
                    }
                    break;
                case 'r':
                    if (event.ctrlKey || event.metaKey) {
                        event.preventDefault();
                        this.resetDemo();
                    }
                    break;
            }
        });
        
        console.log('Keyboard shortcuts configured:');
        console.log('  Ctrl/Cmd + 1: Quick Start Demo');
        console.log('  Ctrl/Cmd + 2: Full Flow Demo');
        console.log('  Ctrl/Cmd + 3: Security Demo');
        console.log('  Ctrl/Cmd + R: Reset Demo');
    }

    /**
     * Setup global error handling
     */
    setupErrorHandling() {
        window.addEventListener('error', (event) => {
            console.error('Global error:', event.error);
            if (window.UIController) {
                window.UIController.showError(`Application error: ${event.error.message}`);
            }
        });
        
        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled promise rejection:', event.reason);
            if (window.UIController) {
                window.UIController.showError(`Promise rejection: ${event.reason.message || event.reason}`);
            }
        });
    }

    /**
     * Show loading state
     */
    showLoadingState() {
        const loadingElement = document.getElementById('loading-state');
        if (loadingElement) {
            loadingElement.style.display = 'block';
        }
        
        document.body.classList.add('loading');
    }

    /**
     * Hide loading state
     */
    hideLoadingState() {
        const loadingElement = document.getElementById('loading-state');
        if (loadingElement) {
            loadingElement.style.display = 'none';
        }
        
        document.body.classList.remove('loading');
    }

    /**
     * Show welcome message
     */
    showWelcomeMessage() {
        if (window.UIController) {
            window.UIController.showSuccess('HSM Attestation Wallet Demo ready!');
            window.UIController.showInfo('Use the navigation tabs to explore different features');
            window.UIController.showInfo('Click "Initialize All" to start the demo');
        }
    }

    /**
     * Show initialization error
     */
    showInitializationError(error) {
        console.error('Demo initialization error:', error);
        
        const errorElement = document.getElementById('error-state');
        if (errorElement) {
            errorElement.style.display = 'block';
            errorElement.innerHTML = `
                <h3>Initialization Failed</h3>
                <p>The demo failed to initialize properly:</p>
                <p><strong>${error.message}</strong></p>
                <button onclick="location.reload()">Reload Page</button>
            `;
        }
        
        this.hideLoadingState();
    }

    /**
     * Reset entire demo
     */
    async resetDemo() {
        try {
            console.log('🔄 Resetting demo...');
            
            if (window.UIController) {
                window.UIController.showInfo('Resetting all services...');
            }
                        
            if (this.services.oauth2) {
                await this.services.oauth2.reset();
            }
            
            if (this.services.attestation) {
                await this.services.attestation.reset();
            }
            
            if (this.services.biometric) {
                await this.services.biometric.reset();
            }
            
            if (this.services.hsm) {
                await this.services.hsm.reset();
            }
            
            console.log('✅ Demo reset complete');
            
            if (window.UIController) {
                window.UIController.showSuccess('Demo reset complete');
            }
            
        } catch (error) {
            console.error('❌ Demo reset failed:', error);
            
            if (window.UIController) {
                window.UIController.showError(`Reset failed: ${error.message}`);
            }
        }
    }

    /**
     * Get demo status
     */
    getStatus() {
        return {
            initialized: this.initialized,
            services: Object.keys(this.services).reduce((status, serviceName) => {
                const service = this.services[serviceName];
                status[serviceName] = service && service.getStatus ? service.getStatus() : { available: false };
                return status;
            }, {}),
            scenarios: Object.keys(this.demoScenarios)
        };
    }

    /**
     * Export demo state for debugging
     */
    exportState() {
        return {
            status: this.getStatus(),
            services: {
                hsm: this.services.hsm?.getStatus(),
                biometric: this.services.biometric?.getStatus(),
                attestation: this.services.attestation?.getStatus(),
                oauth2: this.services.oauth2?.getStatus()
            },
            timestamp: Date.now()
        };
    }

    // ====================================
    // State Management for OAuth Callback
    // ====================================

    /**
     * Check if current page load is from OAuth callback
     */
    isOAuthCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.has('code') || urlParams.has('error');
    }

    /**
     * Check if we should restore previous state
     */
    shouldRestoreState() {
        return localStorage.getItem('hsm-wallet-state') !== null;
    }

    /**
     * Save current application state before OAuth redirect
     */
    saveApplicationState() {
        try {
            const state = {
                initialized: this.initialized,
                servicesInitialized: Object.keys(this.services).length > 0,
                servicesStatus: {},
                timestamp: Date.now(),
                currentView: this.uiController?.currentView || 'overview'
            };

            // Save service states
            Object.keys(this.services).forEach(serviceName => {
                const service = this.services[serviceName];
                if (service && typeof service.getStatus === 'function') {
                    state.servicesStatus[serviceName] = service.getStatus();
                }
            });

            localStorage.setItem('hsm-wallet-state', JSON.stringify(state));
            console.log('💾 Application state saved for OAuth callback', state);

        } catch (error) {
            console.error('❌ Failed to save application state:', error);
        }
    }

    /**
     * Restore application state after OAuth callback
     */
    async restoreApplicationState() {
        try {
            const savedStateJson = localStorage.getItem('hsm-wallet-state');
            if (!savedStateJson) {
                console.log('⚠️ No saved state found, initializing fresh...');
                await this.initializeFresh();
                return;
            }

            const savedState = JSON.parse(savedStateJson);
            console.log('🔄 Restoring application state:', savedState);

            // Check if saved state is too old (more than 1 hour)
            const stateAge = Date.now() - savedState.timestamp;
            if (stateAge > 60 * 60 * 1000) {
                console.log('⚠️ Saved state too old, initializing fresh...');
                localStorage.removeItem('hsm-wallet-state');
                await this.initializeFresh();
                return;
            }

            this.showLoadingState();

            // Restore services - always reinitialize to ensure proper state
            console.log('🔧 Re-initializing services...');
            await this.initializeServices();
            
            // Wait for UI Controller to be ready
            await this.initializeUI();
            
            // Switch to OAuth view to show the results
            if (window.UIController) {
                console.log('🔄 Switching to OAuth2 view...');
                window.UIController.switchView('oauth2');
                
                // Update all status displays
                window.UIController.updateAllStatus();
                window.UIController.updateSystemStatus();
            }

            this.hideLoadingState();
            this.initialized = true;
            console.log('✅ Application state restored successfully');

        } catch (error) {
            console.error('❌ Failed to restore application state:', error);
            // Fall back to fresh initialization
            localStorage.removeItem('hsm-wallet-state');
            await this.initializeFresh();
        }
    }

    /**
     * Handle OAuth callback and restore state
     */
    async handleOAuthCallback() {
        try {
            console.log('📥 Processing OAuth callback...');

            // First, restore the application services
            await this.restoreApplicationState();

            // Ensure UI controller has services registered
            if (window.UIController) {
                console.log('🔄 Re-registering services with UI Controller...');
                window.UIController.registerServices(this.services);
                window.UIController.updateAllStatus();
            }

            // Then let the UI controller handle the OAuth callback
            if (window.UIController && typeof window.UIController.handleOAuthCallback === 'function') {
                await window.UIController.handleOAuthCallback();
            }

            // Update system status after callback processing
            if (window.UIController) {
                window.UIController.updateSystemStatus();
            }

            // Clean up the saved state
            localStorage.removeItem('hsm-wallet-state');
            console.log('🧹 OAuth callback processed, state cleaned up');

        } catch (error) {
            console.error('❌ Failed to handle OAuth callback:', error);
            // Fall back to fresh initialization
            localStorage.removeItem('hsm-wallet-state');
            await this.initializeFresh();
        }
    }

    /**
     * Initialize application fresh (without state restoration)
     */
    async initializeFresh() {
        console.log('🆕 Initializing fresh application...');
        this.showLoadingState();
        await this.initializeServices();
        this.hideLoadingState();
    }

    /**
     * Clear all saved state (for testing/debugging)
     */
    clearSavedState() {
        localStorage.removeItem('hsm-wallet-state');
        console.log('🗑️ Saved state cleared');
    }

    /**
     * Manual initialization for debugging (call from console)
     */
    async manualInit() {
        try {
            console.log('🔧 Manual initialization started...');
            
            // Create services if they don't exist
            if (!this.services || Object.keys(this.services).length === 0) {
                console.log('Creating services...');
                await this.initializeServices();
            }
            
            // Register with UI Controller
            if (window.UIController) {
                console.log('Registering services with UI Controller...');
                window.UIController.registerServices(this.services);
                console.log('✅ Manual initialization completed');
                return true;
            } else {
                console.error('❌ UI Controller not found');
                return false;
            }
        } catch (error) {
            console.error('❌ Manual initialization failed:', error);
            return false;
        }
    }
}

// Global access for debugging
window.HSMWalletDemo = HSMAttestationWalletDemo;

// Start the demo
const demo = new HSMAttestationWalletDemo();

// Export demo instance globally for console access and UI controller access
window.demo = demo;
window.HSMWalletApp = demo;

console.log('🔐 HSM Attestation Wallet Demo loaded');
console.log('Access demo instance via: window.demo or window.HSMWalletApp');
console.log('Available scenarios:', Object.keys(demo.demoScenarios || {}));
console.log('Use demo.runScenario(name) to run scenarios programmatically');