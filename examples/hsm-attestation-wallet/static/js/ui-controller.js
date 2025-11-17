/**
 * UI Controller
 * 
 * Manages the user interface for the HSM Attestation Wallet demo,
 * coordinating between all services and providing real-time feedback.
 */

class UIController {
    constructor() {
        this.initialized = false;
        this.services = {};
        this.logContainer = null;
        this.statusContainer = null;
        this.currentView = 'overview';
        
        // Event handlers
        this.eventHandlers = new Map();
        
        // Dependency state tracking
        this.dependencyStates = {
            hsmInitialized: false,
            biometricEnrolled: false,
            attestationCreated: false,
            clientRegistered: false,
            oauth2FlowCompleted: false
        };
        
        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }
    }

    /**
     * Initialize UI controller
     */
    async initialize() {
        try {
            console.log('Initializing UI Controller...');
            
            // Get DOM elements
            this.setupDOMElements();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Initialize view state
            this.initializeViewState();
            
            this.initialized = true;
            
            // Setup global logging function for services
            this.setupGlobalLogging();
            
            // Signal that UI Controller is ready
            window.dispatchEvent(new CustomEvent('uiControllerReady'));
            
            // Auto-initialize services after a short delay
            setTimeout(() => this.autoInitializeServices(), 1000);
            
            console.log('UI Controller initialized successfully');
            
        } catch (error) {
            console.error('UI Controller initialization failed:', error);
            this.showError('Failed to initialize user interface');
        }
    }

    /**
     * Auto-initialize services when application starts
     */
    async autoInitializeServices() {
        try {
            console.log('🔄 Checking for registered services...');
            
            // Check if services are already registered
            if (!this.services || Object.keys(this.services).length === 0) {
                console.log('No services registered yet, waiting for main demo to register them...');
                
                // Wait for services to be registered by the main demo
                await new Promise(resolve => {
                    const checkServices = () => {
                        if (this.services && Object.keys(this.services).length > 0) {
                            console.log('✅ Services found, proceeding...');
                            resolve();
                        } else {
                            // Check again in 500ms
                            setTimeout(checkServices, 500);
                        }
                    };
                    
                    // Start checking
                    checkServices();
                    
                    // Timeout after 10 seconds
                    setTimeout(() => {
                        console.warn('⚠️ Timeout waiting for services, proceeding anyway...');
                        resolve();
                    }, 10000);
                });
            }
            
            // Services should now be available
            if (this.services && Object.keys(this.services).length > 0) {
                console.log('✅ Services available, updating UI...');
                this.updateAllStatus();
                this.updateButtonStates();
                console.log('✅ Auto-initialization completed successfully');
            } else {
                console.warn('⚠️ No services available after waiting');
            }
            
        } catch (error) {
            console.error('❌ Auto-initialization failed:', error);
            // Don't show error to user, just log it
        }
    }

    /**
     * Setup global logging function for services
     */
    setupGlobalLogging() {
        // Create a global logging function that services can use
        window.logToUI = (service, message, type = 'info') => {
            const timestamp = new Date().toLocaleTimeString();
            this.addLog(service, timestamp, message, type);
        };
        
        // Also override console.log to capture service logs
        const originalConsoleLog = console.log;
        console.log = (...args) => {
            // Call original console.log
            originalConsoleLog.apply(console, args);
            
            // Try to extract service and message from log
            const message = args.join(' ');
            let service = 'unknown';
            let logMessage = message;
            
            // Extract service from [SERVICE] format
            const serviceMatch = message.match(/^\[([^\]]+)\]\s*(.+)$/);
            if (serviceMatch) {
                service = serviceMatch[1].toLowerCase();
                logMessage = serviceMatch[2];
            }
            
            // Add to UI logs
            const timestamp = new Date().toLocaleTimeString();
            this.addLog(service, timestamp, logMessage);
        };
    }

    /**
     * Setup DOM element references
     */
    setupDOMElements() {
        // Main containers
        this.logContainer = document.getElementById('demo-logs');
        this.statusContainer = document.getElementById('status-display');
        
        // Navigation
        this.navButtons = document.querySelectorAll('.nav-button');
        this.demoSections = document.querySelectorAll('.demo-section');
        
        // Status indicators
        this.statusIndicators = {
            system: document.getElementById('system-status')
        };
        
        // Action buttons
        this.actionButtons = {
            initializeAll: document.getElementById('initialize-all'),
            resetAll: document.getElementById('reset-all'),
            generateKey: document.getElementById('generate-key'),
            showHsmDetails: document.getElementById('show-hsm-details'),
            createAttestationCert: document.getElementById('create-attestation-cert'),
            enrollBiometric: document.getElementById('enroll-biometric'),
            authenticateBio: document.getElementById('authenticate-bio'),
            createAttestation: document.getElementById('create-attestation'),
            verifyAttestation: document.getElementById('verify-attestation'),
            registerOAuth: document.getElementById('register-oauth'),
            startOAuth: document.getElementById('start-oauth'),
            startOAuthSameWindow: document.getElementById('start-oauth-same-window'),
            getUserInfo: document.getElementById('get-userinfo')
        };
        
        // Display areas
        this.displayAreas = {
            hsmResult: document.getElementById('hsm-result'),
            biometricResult: document.getElementById('biometric-result'),
            attestationResult: document.getElementById('attestation-result'),
            oauthResult: document.getElementById('oauth-result')
        };
        
        // Form elements
        this.forms = {
            biometricForm: document.getElementById('biometric-form')
        };
    }

    /**
     * Setup event listeners for UI elements
     */
    setupEventListeners() {
        // Navigation
        this.navButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const view = e.target.dataset.view;
                this.switchView(view);
            });
        });
        
        // Action buttons
        if (this.actionButtons.initializeAll) {
            this.actionButtons.initializeAll.addEventListener('click', () => this.initializeAllServices());
        }
        
        if (this.actionButtons.resetAll) {
            this.actionButtons.resetAll.addEventListener('click', () => this.resetAllServices());
        }
        
        // HSM buttons
        if (this.actionButtons.generateKey) {
            this.actionButtons.generateKey.addEventListener('click', () => this.generateHsmKey());
        }
        
        if (this.actionButtons.showHsmDetails) {
            this.actionButtons.showHsmDetails.addEventListener('click', () => this.showHsmDetails());
        }
        
        if (this.actionButtons.createAttestationCert) {
            this.actionButtons.createAttestationCert.addEventListener('click', () => this.createAttestationCertificate());
        }
        
        if (this.actionButtons.enrollBiometric) {
            this.actionButtons.enrollBiometric.addEventListener('click', () => this.enrollBiometric());
        }
        
        if (this.actionButtons.authenticateBio) {
            this.actionButtons.authenticateBio.addEventListener('click', () => this.authenticateBiometric());
        }
        
        if (this.actionButtons.createAttestation) {
            this.actionButtons.createAttestation.addEventListener('click', () => this.createAttestation());
        }
        
        if (this.actionButtons.verifyAttestation) {
            this.actionButtons.verifyAttestation.addEventListener('click', () => this.verifyAttestation());
        }
        
        if (this.actionButtons.registerOAuth) {
            this.actionButtons.registerOAuth.addEventListener('click', () => this.registerOAuthClient());
        }
        
        if (this.actionButtons.startOAuth) {
            this.actionButtons.startOAuth.addEventListener('click', () => this.startOAuthFlow());
        }
        
        if (this.actionButtons.startOAuthSameWindow) {
            this.actionButtons.startOAuthSameWindow.addEventListener('click', () => this.startOAuthFlowSameWindow());
        }
        
        if (this.actionButtons.getUserInfo) {
            this.actionButtons.getUserInfo.addEventListener('click', () => this.fetchAndDisplayUserInfo());
        }
                
    }

    /**
     * Initialize view state
     */
    initializeViewState() {
        this.switchView('overview');
        this.updateAllStatus();
        this.updateButtonStates();
    }

    /**
     * Update button states based on dependency chain
     */
    updateButtonStates() {
        console.log('🔄 Updating button states based on dependencies:', this.dependencyStates);
        
        // HSM buttons - enabled when HSM is initialized
        const hsmEnabled = this.dependencyStates.hsmInitialized;
        this.setButtonEnabled('generateKey', hsmEnabled);
        this.setButtonEnabled('showHsmDetails', hsmEnabled);
        this.setButtonEnabled('createAttestationCert', hsmEnabled);
        
        // Biometric buttons - enabled when HSM is initialized
        const biometricEnabled = this.dependencyStates.hsmInitialized;
        this.setButtonEnabled('enrollBiometric', biometricEnabled);
        this.setButtonEnabled('authenticateBio', biometricEnabled && this.dependencyStates.biometricEnrolled);
        
        // Attestation buttons - enabled when HSM and biometric are ready
        const attestationEnabled = this.dependencyStates.hsmInitialized && this.dependencyStates.biometricEnrolled;
        this.setButtonEnabled('createAttestation', attestationEnabled);
        this.setButtonEnabled('verifyAttestation', attestationEnabled && this.dependencyStates.attestationCreated);
        
        // OAuth2 buttons - enabled based on dependency chain
        const clientRegistrationEnabled = this.dependencyStates.hsmInitialized && 
                                        this.dependencyStates.biometricEnrolled && 
                                        this.dependencyStates.attestationCreated;
        this.setButtonEnabled('registerOAuth', clientRegistrationEnabled);
        
        const oauthFlowEnabled = clientRegistrationEnabled && this.dependencyStates.clientRegistered;
        this.setButtonEnabled('startOAuth', oauthFlowEnabled);
        this.setButtonEnabled('startOAuthSameWindow', oauthFlowEnabled);
        
        const userInfoEnabled = oauthFlowEnabled && this.dependencyStates.oauth2FlowCompleted;
        this.setButtonEnabled('getUserInfo', userInfoEnabled);
    }

    /**
     * Set button enabled/disabled state with visual feedback
     */
    setButtonEnabled(buttonId, enabled) {
        const button = this.actionButtons[buttonId];
        if (!button) return;
        
        button.disabled = !enabled;
        
        if (enabled) {
            button.classList.remove('btn-disabled', 'btn-secondary');
            button.classList.add('btn-primary');
            button.title = '';
        } else {
            button.classList.remove('btn-primary');
            button.classList.add('btn-disabled', 'btn-secondary');
            button.title = 'Complete previous steps first';
        }
    }

    /**
     * Register services with UI controller
     */
    registerServices(services) {
        console.log('DEBUG: UI Controller registerServices called');
        console.log('DEBUG: Services received:', services);
        console.log('DEBUG: HSM service:', services.hsm);
        console.log('DEBUG: Biometric service:', services.biometric);
        console.log('DEBUG: Biometric.hsm reference:', services.biometric ? services.biometric.hsm : 'N/A');
        
        this.services = services;
        
        // Add event listeners to services
        Object.keys(services).forEach(serviceName => {
            const service = services[serviceName];
            if (service && typeof service.addEventListener === 'function') {
                service.addEventListener((event) => this.handleServiceEvent(serviceName, event));
            }
        });
        
        // Check current status of services and update dependency states
        this.updateDependencyStatesFromServiceStatus();
        
        this.updateAllStatus();
        this.updateButtonStates();
    }

    /**
     * Handle service events
     */
    handleServiceEvent(serviceName, event) {
        console.log(`Service event: ${serviceName} - ${event.type}`, event.data);
        
        // Update status indicators
        this.updateServiceStatus(serviceName);
        
        // Update dependency states based on events
        this.updateDependencyStates(serviceName, event);
        
        // Update button states after dependency changes
        this.updateButtonStates();
        
        // Handle specific events
        switch (event.type) {
            case 'initialized':
                this.showSuccess(`${serviceName} initialized successfully`);
                break;
            case 'error':
                this.showError(`${serviceName} error: ${event.data.message}`);
                break;
            case 'biometricEnrolled':
                this.updateBiometricResult(event.data);
                break;
            case 'biometricAuthenticated':
                this.updateBiometricResult(event.data);
                break;
            case 'tokenCreated':
                this.updateAttestationResult(event.data);
                break;
            case 'clientRegistered':
                this.updateOAuthResult(event.data);
                break;
        }
    }

    /**
     * Update dependency states based on current service status
     */
    updateDependencyStatesFromServiceStatus() {
        console.log('🔄 Updating dependency states from current service status...');
        
        // Check HSM status
        if (this.services.hsm) {
            const hsmStatus = this.services.hsm.getStatus ? this.services.hsm.getStatus() : {};
            if (hsmStatus.initialized) {
                this.dependencyStates.hsmInitialized = true;
                console.log('✅ HSM dependency satisfied (already initialized)');
            }
        }
        
        // Check biometric status
        if (this.services.biometric) {
            const bioStatus = this.services.biometric.getStatus ? this.services.biometric.getStatus() : {};
            if (bioStatus.initialized && bioStatus.enrolledUsers > 0) {
                this.dependencyStates.biometricEnrolled = true;
                console.log('✅ Biometric enrollment dependency satisfied (already enrolled)');
            }
        }
        
        // Check attestation status
        if (this.services.attestation) {
            const attestStatus = this.services.attestation.getStatus ? this.services.attestation.getStatus() : {};
            if (attestStatus.initialized && attestStatus.tokensCreated > 0) {
                this.dependencyStates.attestationCreated = true;
                console.log('✅ Attestation creation dependency satisfied (tokens already created)');
            }
        }
        
        // Check OAuth2 status
        if (this.services.oauth2) {
            const oauthStatus = this.services.oauth2.getStatus ? this.services.oauth2.getStatus() : {};
            if (oauthStatus.clientRegistered) {
                this.dependencyStates.clientRegistered = true;
                console.log('✅ Client registration dependency satisfied (already registered)');
            }
            if (oauthStatus.hasTokens) {
                this.dependencyStates.oauth2FlowCompleted = true;
                console.log('✅ OAuth2 flow completion dependency satisfied (tokens already received)');
            }
        }
        
        console.log('✅ Dependency states updated from service status:', this.dependencyStates);
    }

    /**
     * Update dependency states based on service events
     */
    updateDependencyStates(serviceName, event) {
        switch (serviceName) {
            case 'hsm':
                if (event.type === 'initialized') {
                    this.dependencyStates.hsmInitialized = true;
                    console.log('✅ HSM initialization dependency satisfied');
                }
                break;
                
            case 'biometric':
                if (event.type === 'enrolled') {
                    this.dependencyStates.biometricEnrolled = true;
                    console.log('✅ Biometric enrollment dependency satisfied');
                } else if (event.type === 'reset') {
                    // Reset biometric enrollment state when biometric is reset
                    this.dependencyStates.biometricEnrolled = false;
                    console.log('🔄 Biometric enrollment dependency reset');
                }
                break;
                
            case 'attestation':
                if (event.type === 'tokenCreated') {
                    this.dependencyStates.attestationCreated = true;
                    console.log('✅ Attestation creation dependency satisfied');
                }
                break;
                
            case 'oauth2':
                if (event.type === 'clientRegistered') {
                    this.dependencyStates.clientRegistered = true;
                    console.log('✅ Client registration dependency satisfied');
                } else if (event.type === 'tokensReceived') {
                    this.dependencyStates.oauth2FlowCompleted = true;
                    console.log('✅ OAuth2 flow completion dependency satisfied');
                }
                break;
        }
    }

    /**
     * Switch between demo views
     */
    switchView(viewName) {
        // Update navigation
        this.navButtons.forEach(button => {
            if (button.dataset.view === viewName) {
                button.classList.add('active');
            } else {
                button.classList.remove('active');
            }
        });
        
        // Update sections
        this.demoSections.forEach(section => {
            if (section.id === `${viewName}-section`) {
                section.style.display = 'block';
            } else {
                section.style.display = 'none';
            }
        });
        
        this.currentView = viewName;
        
        // Update view-specific content
        this.updateViewContent(viewName);
    }

    /**
     * Update view-specific content
     */
    updateViewContent(viewName) {
        switch (viewName) {
            case 'overview':
                this.updateAllStatus();
                break;
            case 'hsm':
                this.updateHsmDisplay();
                break;
        }
    }

    /**
     * Initialize all services
     */
    async initializeAllServices() {
        try {
            this.showInfo('Checking service initialization...');
            
            console.log('DEBUG: this.services:', this.services);
            console.log('DEBUG: Object.keys(this.services):', Object.keys(this.services || {}));
            console.log('DEBUG: Services count:', Object.keys(this.services || {}).length);
            
            // Check if services exist
            if (!this.services || Object.keys(this.services).length === 0) {
                console.error('DEBUG: Services check failed!');
                console.error('DEBUG: this.services is null/undefined:', !this.services);
                console.error('DEBUG: this.services keys length is 0:', Object.keys(this.services || {}).length === 0);
                
                // Try to get services from the global app instance
                if (window.HSMWalletApp && window.HSMWalletApp.services) {
                    console.log('DEBUG: Found services in global app, using those...');
                    this.services = window.HSMWalletApp.services;
                } else if (window.demo && window.demo.services) {
                    console.log('DEBUG: Found services in demo instance, using those...');
                    this.services = window.demo.services;
                } else {
                    console.error('DEBUG: No services found anywhere');
                    throw new Error('Services not registered. Please refresh the page and wait for automatic initialization.');
                }
            }
            
            // Step 1: Initialize HSM first
            if (this.services.hsm) {
                if (this.services.hsm.initialized) {
                    this.showInfo('HSM already initialized, skipping...');
                } else {
                    this.showInfo('Initializing HSM...');
                    console.log('DEBUG: About to initialize HSM');
                    
                    await this.services.hsm.initialize();
                    
                    console.log('DEBUG: HSM initialized, status:', this.services.hsm.initialized);
                    
                    // Verify HSM is actually initialized before proceeding
                    if (!this.services.hsm.initialized) {
                        throw new Error('HSM failed to initialize properly');
                    }
                    
                    // Update dependency state
                    this.dependencyStates.hsmInitialized = true;
                    this.updateButtonStates();
                }
            } else {
                throw new Error('HSM service not found');
            }
            
            // Step 2: Initialize biometric with extra safety checks
            if (this.services.biometric) {
                if (this.services.biometric.initialized) {
                    this.showInfo('Biometric authentication already initialized, skipping...');
                } else {
                    this.showInfo('Initializing biometric authentication...');
                    console.log('DEBUG: About to initialize biometric');
                    console.log('DEBUG: Biometric HSM reference exists?', !!this.services.biometric.hsm);
                    console.log('DEBUG: Biometric HSM initialized?', this.services.biometric.hsm ? this.services.biometric.hsm.initialized : 'N/A');
                    
                    // Double-check that biometric has proper HSM reference
                    if (!this.services.biometric.hsm) {
                        this.services.biometric.hsm = this.services.hsm;
                        this.showInfo('Fixed missing HSM reference in biometric service');
                    }
                    
                    await this.services.biometric.initialize();
                    console.log('DEBUG: Biometric initialized');
                }
            }
            
            // Step 3: Initialize remaining services
            if (this.services.attestation) {
                if (this.services.attestation.initialized) {
                    this.showInfo('Attestation service already initialized, skipping...');
                } else {
                    this.showInfo('Initializing attestation service...');
                    await this.services.attestation.initialize();
                }
            }
            
            if (this.services.oauth2) {
                this.showInfo('Initializing OAuth2 client...');
                await this.services.oauth2.initialize();
            }
            
            this.showSuccess('All services initialized successfully!');
            this.updateAllStatus();
            this.updateButtonStates();
            
        } catch (error) {
            console.error('DEBUG: Service initialization error:', error);
            this.showError(`Service initialization failed: ${error.message}`);
        }
    }

    /**
     * Reset all services
     */
    async resetAllServices() {
        try {
            this.showInfo('Resetting all services...');
            
            // Reset dependency states
            this.dependencyStates = {
                hsmInitialized: false,
                biometricEnrolled: false,
                attestationCreated: false,
                clientRegistered: false,
                oauth2FlowCompleted: false
            };
            
            // Update button states immediately
            this.updateButtonStates();
            
            // Reset in reverse order to avoid dependencies
            if (this.services.oauth2) {
                this.showInfo('Resetting OAuth2 client...');
                await this.services.oauth2.reset();
            }
            
            if (this.services.attestation) {
                this.showInfo('Resetting attestation service...');
                await this.services.attestation.reset();
            }
            
            if (this.services.biometric) {
                this.showInfo('Resetting biometric authentication...');
                await this.services.biometric.reset();
            }
            
            if (this.services.hsm) {
                this.showInfo('Resetting HSM...');
                await this.services.hsm.reset();
            }
            
            // Clear UI results
            this.clearAllResults();
            
            this.showSuccess('All services reset successfully!');
            this.updateAllStatus();
            
        } catch (error) {
            this.showError(`Service reset failed: ${error.message}`);
        }
    }

    // ====================================
    // HSM Operations
    // ====================================

    /**
     * Generate a new HSM key
     */
    async generateHsmKey() {
        try {
            if (!this.services.hsm || !this.services.hsm.initialized) {
                this.showError('HSM not initialized. Please initialize services first.');
                return;
            }

            this.showInfo('Generating new HSM key...');
            
            const keyId = await this.services.hsm.generateKeyPair();
            
            this.showSuccess(`HSM key generated successfully: ${keyId}`);
            
            // Update display
            this.updateHsmDisplay();
            
        } catch (error) {
            console.error('Key generation error:', error);
            this.showError(`Key generation failed: ${error.message}`);
        }
    }

    /**
     * Show detailed HSM information
     */
    async showHsmDetails() {
        try {
            if (!this.services.hsm || !this.services.hsm.initialized) {
                this.showError('HSM not initialized. Please initialize services first.');
                return;
            }

            this.showInfo('Displaying HSM details...');
            
            // Call the new displayDetailedInfo method
            this.services.hsm.displayDetailedInfo();
            
            // Also update the display area
            this.updateHsmDisplay();
            
        } catch (error) {
            console.error('HSM details error:', error);
            this.showError(`Failed to show HSM details: ${error.message}`);
        }
    }

    /**
     * Create attestation certificate for the latest key
     */
    async createAttestationCertificate() {
        try {
            if (!this.services.hsm || !this.services.hsm.initialized) {
                this.showError('HSM not initialized. Please initialize services first.');
                return;
            }

            const keys = this.services.hsm.listKeys();
            if (keys.length === 0) {
                this.showError('No keys available. Generate a key first.');
                return;
            }

            // Use the most recent key
            const latestKey = keys[keys.length - 1];
            this.showInfo(`Creating attestation certificate for key: ${latestKey.keyId}`);
            
            const certificate = await this.services.hsm.generateKeyAttestation(latestKey.keyId);
            
            this.showSuccess(`Attestation certificate created for key: ${latestKey.keyId}`);
            
            // Update display
            this.updateHsmDisplay();
            
        } catch (error) {
            console.error('Attestation certificate error:', error);
            this.showError(`Failed to create attestation certificate: ${error.message}`);
        }
    }

    /**
     * Update HSM display area
     */
    updateHsmDisplay() {
        try {
            if (!this.services.hsm || !this.displayAreas.hsmResult) {
                return;
            }

            const status = this.services.hsm.getStatus();
            const keyDetails = this.services.hsm.getDetailedKeyInfo();

            let html = `
                <div class="status-info">
                    <h4>HSM Status</h4>
                    <div class="status-grid">
                        <div class="status-item">
                            <strong>Device ID:</strong> ${status.deviceId || 'Not initialized'}
                        </div>
                        <div class="status-item">
                            <strong>Security State:</strong> 
                            <span class="${status.securityState === 'secure' ? 'text-success' : 'text-error'}">
                                ${status.securityState || 'Unknown'}
                            </span>
                        </div>
                        <div class="status-item">
                            <strong>Keys Generated:</strong> ${status.keyCount || 0}
                        </div>
                        <div class="status-item">
                            <strong>Boot Count:</strong> ${status.bootCount || 0}
                        </div>
                    </div>
                </div>
            `;

            if (keyDetails && keyDetails.length > 0) {
                html += `
                    <div class="keys-info">
                        <h4>Generated Keys</h4>
                        <div class="keys-list">
                `;

                keyDetails.forEach((key, index) => {
                    html += `
                        <div class="key-item">
                            <div class="key-header">
                                <strong>Key #${index + 1}: ${key.keyId}</strong>
                            </div>
                            <div class="key-details">
                                <div class="detail-row">
                                    <span class="label">Algorithm:</span>
                                    <span class="value">${key.algorithm} (${key.keyType}-${key.curve})</span>
                                </div>
                                <div class="detail-row">
                                    <span class="label">Created:</span>
                                    <span class="value">${key.createdAt}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="label">Security:</span>
                                    <span class="value">${key.securityLevel} ${key.hardwareBacked ? '(Hardware)' : '(Software)'}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="label">Fingerprint:</span>
                                    <span class="value monospace">${key.publicKeyFingerprint}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="label">Attestation:</span>
                                    <span class="value ${key.hasAttestation ? 'text-success' : 'text-warning'}">
                                        ${key.hasAttestation ? '✅ Available' : '⏳ Not Generated'}
                                    </span>
                                </div>
                            </div>
                        </div>
                    `;
                });

                html += `
                        </div>
                    </div>
                `;
            }

            this.displayAreas.hsmResult.innerHTML = html;

        } catch (error) {
            console.error('HSM display update error:', error);
        }
    }

    /**
     * Enroll biometric
     */
    async enrollBiometric() {
        try {
            this.showInfo('Enrolling biometric...');
            
            if (!this.services.biometric) {
                throw new Error('Biometric service not available');
            }
            
            const result = await this.services.biometric.enrollBiometric('demouser', 'fingerprint');
            this.updateBiometricResult(result);
            
            // Update dependency state
            this.dependencyStates.biometricEnrolled = true;
            this.updateButtonStates();
            
        } catch (error) {
            this.showError(`Biometric enrollment failed: ${error.message}`);
        }
    }

    /**
     * Authenticate biometric
     */
    async authenticateBiometric() {
        try {
            // Check if user is enrolled first
            if (!this.dependencyStates.biometricEnrolled) {
                this.showError('Please enroll biometric first before attempting authentication.');
                return;
            }
            
            this.showInfo('Authenticating biometric...');
            
            if (!this.services.biometric) {
                throw new Error('Biometric service not available');
            }
            
            const result = await this.services.biometric.authenticateBiometric('demouser');
            this.updateBiometricResult(result);
            
        } catch (error) {
            this.showError(`Biometric authentication failed: ${error.message}`);
        }
    }

    /**
     * Create attestation token
     */
    async createAttestation() {
        try {
            this.showInfo('Creating attestation token...');
            
            if (!this.services.attestation) {
                throw new Error('Attestation service not available');
            }
            
            const token = await this.services.attestation.createAttestationToken({
                subject: 'demo-user',
                audience: 'demo-app',
                bioAuth: true,
                bioType: 'fingerprint'
            });
            
            this.updateAttestationResult({ token: token });
            
            // Update dependency state
            this.dependencyStates.attestationCreated = true;
            this.updateButtonStates();
            
        } catch (error) {
            this.showError(`Attestation creation failed: ${error.message}`);
        }
    }

    /**
     * Verify attestation token
     */
    async verifyAttestation() {
        try {
            const attestationResult = this.displayAreas.attestationResult;
            if (!attestationResult) return;
            
            const tokenElement = attestationResult.querySelector('.token-display');
            if (!tokenElement) {
                this.showError('No attestation token to verify');
                return;
            }
            
            const token = tokenElement.textContent.trim();
            
            this.showInfo('Verifying attestation token...');
            
            const result = await this.services.attestation.verifyAttestationToken(token);
            this.updateAttestationResult({ verificationResult: result });
            
        } catch (error) {
            this.showError(`Attestation verification failed: ${error.message}`);
        }
    }

    /**
     * Register OAuth2 client
     */
    async registerOAuthClient() {
        try {
            this.showInfo('Registering OAuth2 client...');
            
            if (!this.services.oauth2) {
                throw new Error('OAuth2 service not available');
            }
            
            const result = await this.services.oauth2.registerClient();
            this.updateOAuthResult(result);
            
            // Update dependency state
            this.dependencyStates.clientRegistered = true;
            this.updateButtonStates();
            
        } catch (error) {
            this.showError(`OAuth2 registration failed: ${error.message}`);
        }
    }

    /**
     * Start OAuth flow with same-window redirect (saves state)
     */
    async startOAuthFlowSameWindow() {
        try {
            this.showInfo('Starting OAuth2 authorization flow (same window)...');
            
            if (!this.services.oauth2) {
                throw new Error('OAuth2 service not available');
            }

            // Save application state before redirecting
            if (window.HSMWalletApp && typeof window.HSMWalletApp.saveApplicationState === 'function') {
                window.HSMWalletApp.saveApplicationState();
            }

            const result = await this.services.oauth2.startAuthorizationCodeFlow();
            
            // Instead of opening in new window, redirect current window
            if (result.authUrl) {
                this.showInfo('Redirecting to OAuth2 authorization server...');
                setTimeout(() => {
                    window.location.href = result.authUrl;
                }, 1000); // Small delay to show the message
            }
            
        } catch (error) {
            this.showError(`OAuth2 flow failed: ${error.message}`);
        }
    }

    /**
     * Handle OAuth callback when returning from authorization server
     */
    async handleOAuthCallback() {
        try {
            console.log('🔄 UI Controller: handleOAuthCallback started');
            
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const error = urlParams.get('error');

            console.log('OAuth Callback Parameters:');
            console.log('  - Code:', code ? code.substring(0, 20) + '...' : 'N/A');
            console.log('  - State:', state ? state.substring(0, 20) + '...' : 'N/A');
            console.log('  - Error:', error || 'N/A');

            if (error) {
                this.showError(`OAuth authorization failed: ${error}`);
                return;
            }

            if (!code || !state) {
                console.log('❌ No OAuth callback parameters found');
                return;
            }

            this.showInfo('Processing OAuth callback...');

            if (!this.services.oauth2) {
                console.error('❌ OAuth2 service not available');
                throw new Error('OAuth2 service not available');
            }

            console.log('✅ OAuth2 service available, processing callback...');

            // Handle the callback
            console.log('🔄 Calling handleAuthorizationCallback...');
            const result = await this.services.oauth2.handleAuthorizationCallback(code, state);
            console.log('✅ Authorization callback handled, result:', result);
            
            console.log('🔄 Updating OAuth result display...');
            this.updateOAuthResult(result);

            // Update dependency state for OAuth2 flow completion
            this.dependencyStates.oauth2FlowCompleted = true;
            this.updateButtonStates();

            this.showSuccess('OAuth authorization completed successfully!');

            // Fetch and display userinfo after successful authentication
            console.log('🔄 Fetching userinfo...');
            await this.fetchAndDisplayUserInfo();

            // Clean up URL parameters
            window.history.replaceState({}, document.title, window.location.pathname);

        } catch (error) {
            console.error('❌ OAuth callback error:', error);
            this.showError(`OAuth callback failed: ${error.message}`);
        }
    }

    /**
     * Fetch and display userinfo after successful OAuth authentication
     */
    async fetchAndDisplayUserInfo() {
        try {
            console.log('🔄 Starting userinfo and introspection fetch...');
            this.showInfo('Fetching user information and token introspection...');

            if (!this.services.oauth2) {
                console.error('❌ OAuth2 service not available');
                throw new Error('OAuth2 service not available');
            }

            // Check if we have tokens
            const status = this.services.oauth2.getStatus();
            console.log('OAuth2 Status:', status);
            
            if (!status.hasTokens) {
                console.error('❌ No tokens available for userinfo request');
                throw new Error('No tokens available');
            }

            // Get userinfo from OAuth2 service
            console.log('🔄 Calling getUserInfo()...');
            const userInfo = await this.services.oauth2.getUserInfo();
            console.log('✅ Userinfo received:', userInfo);

            // Get token introspection from OAuth2 service
            console.log('🔄 Calling getTokenIntrospection()...');
            const introspectionData = await this.services.oauth2.getTokenIntrospection();
            console.log('✅ Introspection data received:', introspectionData);

            // Update the OAuth result display to include both userinfo and introspection
            console.log('🔄 Updating UI with userinfo and introspection...');
            this.updateOAuthResultWithUserInfoAndIntrospection(userInfo, introspectionData);
            console.log('✅ UI updated with userinfo and introspection');

            this.showSuccess('User information and token introspection retrieved successfully!');

        } catch (error) {
            console.error('❌ Userinfo/introspection fetch error:', error);
            this.showError(`Failed to fetch user information: ${error.message}`);
        }
    }


    /**
     * Update all service status indicators
     */
    updateAllStatus() {
        Object.keys(this.services).forEach(serviceName => {
            this.updateServiceStatus(serviceName);
        });
    }

    /**
     * Update system status based on all services
     */
    updateSystemStatus() {
        const systemStatus = this.statusIndicators.system;
        if (!systemStatus) return;
        
        const statusText = systemStatus.querySelector('.status-text');
        
        // Check if all key services are initialized
        const keyServices = ['hsm', 'biometric', 'attestation', 'oauth2'];
        const serviceStatuses = keyServices.map(serviceName => {
            const service = this.services[serviceName];
            if (!service) return false;
            const status = service.getStatus ? service.getStatus() : { initialized: false };
            return status.initialized;
        });
        
        const allOnline = serviceStatuses.every(status => status === true);
        const someOnline = serviceStatuses.some(status => status === true);
        
        if (allOnline) {
            systemStatus.classList.add('online');
            systemStatus.classList.remove('partial');
            statusText.textContent = 'System Online';
        } else if (someOnline) {
            systemStatus.classList.remove('online');
            systemStatus.classList.add('partial');
            statusText.textContent = 'Partial Online';
        } else {
            systemStatus.classList.remove('online', 'partial');
            statusText.textContent = 'System Offline';
        }
    }

    /**
     * Update individual service status (legacy method - now updates system status)
     */
    updateServiceStatus(serviceName) {
        this.updateSystemStatus();
    }

    /**
     * Update biometric result display
     */
    updateBiometricResult(data) {
        const resultArea = this.displayAreas.biometricResult;
        if (!resultArea) return;
        
        resultArea.innerHTML = `
            <h4>Biometric Result</h4>
            <div class="result-data">
                <p><strong>Status:</strong> ${data.enrolled ? 'Enrolled' : data.authenticated ? 'Authenticated' : 'Failed'}</p>
                <p><strong>User:</strong> ${data.userId || 'N/A'}</p>
                <p><strong>Type:</strong> ${data.biometricType || 'N/A'}</p>
                <p><strong>Confidence:</strong> ${data.confidence || 'N/A'}</p>
                <p><strong>Timestamp:</strong> ${data.timestamp ? new Date(data.timestamp).toLocaleString() : 'N/A'}</p>
            </div>
        `;
    }

    /**
     * Update attestation result display
     */
    updateAttestationResult(data) {
        const resultArea = this.displayAreas.attestationResult;
        if (!resultArea) return;

        let content = '<h4>Attestation Result</h4><div class="result-data">';

        if (data.token) {
            content += `
                <p><strong>Token Created:</strong> ✅</p>
                <div class="token-display" style="background: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all; font-family: monospace; font-size: 12px; max-height: 150px; overflow-y: auto;">
                    ${data.token}
                </div>
            `;

            // Decode and display JWT details
            try {
                const jwtParts = data.token.split('.');
                if (jwtParts.length === 3) {
                    const header = JSON.parse(atob(jwtParts[0].replace(/-/g, '+').replace(/_/g, '/')));
                    const payload = JSON.parse(atob(jwtParts[1].replace(/-/g, '+').replace(/_/g, '/')));
                    const signature = jwtParts[2];

                    content += `
                        <div style="margin-top: 20px;">
                            <h5 style="color: #2c5aa0; margin-bottom: 10px;"><i class="fas fa-key"></i> JWT Details</h5>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                                <!-- Header -->
                                <div>
                                    <h6 style="color: #495057; margin-bottom: 8px;"><i class="fas fa-header"></i> Header</h6>
                                    <div style="background: #f8f9fa; padding: 10px; border-radius: 4px; border-left: 3px solid #6c757d; font-size: 0.85em;">
                                        <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 4px;">
                                            <strong>Algorithm:</strong> <span>${header.alg || 'N/A'}</span>
                                            <strong>Type:</strong> <span>${header.typ || 'N/A'}</span>
                                            <strong>Key ID:</strong> <span style="font-family: monospace; word-break: break-all;">${header.kid || 'N/A'}</span>
                                            ${header.x5c ? `<strong>x5c Chain:</strong> <span>${header.x5c.length} cert(s)</span>` : ''}
                                        </div>
                                    </div>
                                </div>

                                <!-- Payload -->
                                <div>
                                    <h6 style="color: #495057; margin-bottom: 8px;"><i class="fas fa-file-alt"></i> Payload</h6>
                                    <div style="background: #f8f9fa; padding: 10px; border-radius: 4px; border-left: 3px solid #28a745; font-size: 0.85em;">
                                        <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 4px;">
                                            <strong>Issuer:</strong> <span>${payload.iss || 'N/A'}</span>
                                            <strong>Subject:</strong> <span>${payload.sub || 'N/A'}</span>
                                            <strong>Audience:</strong> <span>${payload.aud || 'N/A'}</span>
                                            <strong>Expires:</strong> <span>${payload.exp ? new Date(payload.exp * 1000).toLocaleString() : 'N/A'}</span>
                                            <strong>Issued:</strong> <span>${payload.iat ? new Date(payload.iat * 1000).toLocaleString() : 'N/A'}</span>
                                            <strong>JWT ID:</strong> <span style="font-family: monospace; word-break: break-all;">${payload.jti || 'N/A'}</span>
                                            ${payload.attestation_jwt ? `<strong>Attestation JWT:</strong> <span>Present (${payload.attestation_jwt.length} chars)</span>` : ''}
                                            ${payload.bio_authenticated !== undefined ? `<strong>Bio Auth:</strong> <span>${payload.bio_authenticated ? '✅ Yes' : '❌ No'}</span>` : ''}
                                            ${payload.hsm_backed !== undefined ? `<strong>HSM Backed:</strong> <span>${payload.hsm_backed ? '✅ Yes' : '❌ No'}</span>` : ''}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Signature -->
                            <div style="margin-top: 15px;">
                                <h6 style="color: #495057; margin-bottom: 8px;"><i class="fas fa-signature"></i> Signature</h6>
                                <div style="background: #f8f9fa; padding: 10px; border-radius: 4px; border-left: 3px solid #dc3545; font-family: monospace; font-size: 0.8em; word-break: break-all;">
                                    ${signature.substring(0, 50)}${signature.length > 50 ? '...' : ''}
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (error) {
                console.warn('Failed to decode JWT:', error);
                content += `<p style="color: #dc3545;"><strong>JWT Decode Error:</strong> ${error.message}</p>`;
            }
        }

        if (data.verificationResult) {
            content += `
                <div style="margin-top: 20px;">
                    <h5 style="color: #2c5aa0; margin-bottom: 10px;"><i class="fas fa-check-circle"></i> Verification Results</h5>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid ${data.verificationResult.valid ? '#28a745' : '#dc3545'};">
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px;">
                            <p><strong>Valid:</strong> ${data.verificationResult.valid ? '✅ Yes' : '❌ No'}</p>
                            <p><strong>Hardware Backed:</strong> ${data.verificationResult.hardwareBacked ? '✅ Yes' : '❌ No'}</p>
                            <p><strong>Security Level:</strong> ${data.verificationResult.securityLevel || 'N/A'}</p>
                        </div>
                        ${data.verificationResult.details ? `<div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #dee2e6;"><strong>Details:</strong> ${data.verificationResult.details}</div>` : ''}
                    </div>
                </div>
            `;
        }

        content += '</div>';
        resultArea.innerHTML = content;
    }

    /**
     * Update OAuth2 result display
     */
    updateOAuthResult(data) {
        const resultArea = this.displayAreas.oauthResult;
        if (!resultArea) return;
        
        let content = '<h4>OAuth2 Result</h4><div class="result-data">';
        
        if (data.client_id) {
            content += `<p><strong>Client ID:</strong> ${data.client_id}</p>`;
        }
        
        if (data.authUrl) {
            const urlId = 'auth-url-' + Date.now();
            content += `
                <p><strong>Authorization URL:</strong></p>
                <div style="position: relative; background: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all; font-family: monospace; font-size: 12px;">
                    <span id="${urlId}">${data.authUrl}</span>
                    <div style="position: absolute; top: 5px; right: 5px; display: flex; gap: 5px;">
                        <button onclick="navigator.clipboard.writeText('${data.authUrl}'); this.textContent='Copied!'; setTimeout(() => this.innerHTML='<i class=\\'fas fa-copy\\'></i>', 1000)" 
                                class="btn btn-sm btn-secondary" title="Copy URL">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button onclick="window.open('${data.authUrl}', '_blank')" 
                                class="btn btn-sm btn-primary" title="Open in New Tab">
                            <i class="fas fa-external-link-alt"></i>
                        </button>
                    </div>
                </div>
            `;
        }
        
        if (data.tokens) {
            content += `
                <p><strong>Access Token:</strong> ${data.tokens.access_token ? '✅ Received' : '❌ Missing'}</p>
                <p><strong>Refresh Token:</strong> ${data.tokens.refresh_token ? '✅ Received' : '❌ Missing'}</p>
                <p><strong>Expires In:</strong> ${data.tokens.expires_in || 'N/A'} seconds</p>
            `;
        }
        
        content += '</div>';
        resultArea.innerHTML = content;
    }

    /**
     * Update OAuth2 result display with userinfo
     */
    updateOAuthResultWithUserInfoAndIntrospection(userInfo, introspectionData) {
        console.log('🔄 updateOAuthResultWithUserInfoAndIntrospection called with:', userInfo, introspectionData);
        
        const resultArea = this.displayAreas.oauthResult;
        if (!resultArea) {
            console.error('❌ OAuth result area not found!');
            return;
        }
        
        console.log('✅ OAuth result area found');
        
        // Get current content and add userinfo and introspection sections
        let currentContent = resultArea.innerHTML;
        console.log('Current content length:', currentContent.length);
        
        // Remove closing tags to add more content
        currentContent = currentContent.replace(/<\/div>\s*$/, '');
        
        // Add userinfo and introspection sections side by side
        const combinedHtml = `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                <!-- User Information Section -->
                <div>
                    <h4 style="color: #2c5aa0;"><i class="fas fa-user"></i> User Information</h4>
                    <div class="userinfo-data" style="background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #28a745;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.9em;">
                            <p><strong>User ID:</strong> ${userInfo.sub || 'N/A'}</p>
                            <p><strong>Email:</strong> ${userInfo.email || 'N/A'}</p>
                            <p><strong>Email Verified:</strong> ${userInfo.email_verified ? '✅ Yes' : '❌ No'}</p>
                            <p><strong>Name:</strong> ${userInfo.name || 'N/A'}</p>
                            <p><strong>Username:</strong> ${userInfo.preferred_username || 'N/A'}</p>
                            <p><strong>Given Name:</strong> ${userInfo.given_name || 'N/A'}</p>
                            <p><strong>Family Name:</strong> ${userInfo.family_name || 'N/A'}</p>
                        </div>
                        ${userInfo.picture ? `<div style="margin-top: 10px;"><strong>Profile Picture:</strong><br><img src="${userInfo.picture}" alt="Profile" style="max-width: 100px; border-radius: 4px; margin-top: 5px;"></div>` : ''}
                    </div>
                </div>
                
                <!-- Token Introspection Section -->
                <div>
                    <h4 style="color: #2c5aa0;"><i class="fas fa-search"></i> Token Introspection</h4>
                    <div class="introspection-data" style="background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #007bff;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.9em;">
                            <p><strong>Active:</strong> ${introspectionData.active ? '✅ Yes' : '❌ No'}</p>
                            <p><strong>Subject:</strong> ${introspectionData.sub || 'N/A'}</p>
                            <p><strong>Client ID:</strong> ${introspectionData.client_id || 'N/A'}</p>
                            <p><strong>Scope:</strong> ${introspectionData.scope || 'N/A'}</p>
                            <p><strong>Token Type:</strong> ${introspectionData.token_type || 'N/A'}</p>
                            <p><strong>Expires:</strong> ${introspectionData.exp ? new Date(introspectionData.exp * 1000).toLocaleString() : 'N/A'}</p>
                            <p><strong>Issued:</strong> ${introspectionData.iat ? new Date(introspectionData.iat * 1000).toLocaleString() : 'N/A'}</p>
                            <p><strong>Issuer State:</strong> ${introspectionData.issuer_state || 'N/A'}</p>
                            ${introspectionData.attestation ? `
                            <div style="margin-top: 15px; padding: 10px; background: #e8f5e8; border-left: 3px solid #28a745; border-radius: 4px;">
                                <h6 style="color: #155724; margin-bottom: 8px;"><i class="fas fa-shield-alt"></i> Attestation Information</h6>
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 4px; font-size: 0.85em;">
                                    <p><strong>Verified:</strong> ${introspectionData.attestation.attestation_verified ? '✅ Yes' : '❌ No'}</p>
                                    <p><strong>Trust Level:</strong> ${introspectionData.attestation.attestation_trust_level || 'N/A'}</p>
                                    <p><strong>Key ID:</strong> <span style="font-family: monospace; word-break: break-all;">${introspectionData.attestation.attestation_key_id || 'N/A'}</span></p>
                                    <p><strong>HSM Backed:</strong> ${introspectionData.attestation.hsm_backed ? '✅ Yes' : '❌ No'}</p>
                                    <p><strong>Bio Auth:</strong> ${introspectionData.attestation.bio_authenticated ? '✅ Yes' : '❌ No'}</p>
                                    <p><strong>Issued:</strong> ${introspectionData.attestation.attestation_issued_at ? new Date(introspectionData.attestation.attestation_issued_at * 1000).toLocaleString() : 'N/A'}</p>
                                    <p><strong>Expires:</strong> ${introspectionData.attestation.attestation_expires_at ? new Date(introspectionData.attestation.attestation_expires_at * 1000).toLocaleString() : 'N/A'}</p>
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
        
        currentContent += combinedHtml;
        
        console.log('🔄 Setting new content (length:', currentContent.length, ')');
        resultArea.innerHTML = currentContent;
        console.log('✅ OAuth result updated with userinfo and introspection');
    }


    /**
     * Clear all result displays
     */
    clearAllResults() {
        Object.values(this.displayAreas).forEach(area => {
            if (area) {
                area.innerHTML = '';
            }
        });
    }

    /**
     * Add log entry
     */
    addLog(service, timestamp, message, type = 'info') {
        // Auto-detect type from message content if not specified
        if (type === 'info') {
            const lowerMessage = message.toLowerCase();
            if (lowerMessage.includes('successfully') || lowerMessage.includes('completed') || lowerMessage.includes('ready') || lowerMessage.includes('initialized')) {
                type = 'success';
            } else if (lowerMessage.includes('failed') || lowerMessage.includes('error') || lowerMessage.includes('invalid') || lowerMessage.includes('denied')) {
                type = 'error';
            } else if (lowerMessage.includes('warning') || lowerMessage.includes('caution') || lowerMessage.includes('partial')) {
                type = 'warning';
            }
        }
        
        if (!this.logContainer) return;
        
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        
        logEntry.innerHTML = `
            <span class="log-time">${timestamp}</span>
            <span class="log-message">[${service.toUpperCase()}] ${message}</span>
        `;
        
        this.logContainer.appendChild(logEntry);
        
        // Auto-scroll to bottom
        this.logContainer.scrollTop = this.logContainer.scrollHeight;
        
        // Limit log entries
        const maxLogs = 100;
        while (this.logContainer.children.length > maxLogs) {
            this.logContainer.removeChild(this.logContainer.firstChild);
        }
    }

    /**
     * Show success message
     */
    showSuccess(message) {
        this.showMessage(message, 'success');
    }

    /**
     * Show error message
     */
    showError(message) {
        this.showMessage(message, 'error');
    }

    /**
     * Show info message
     */
    showInfo(message) {
        this.showMessage(message, 'info');
    }

    /**
     * Show message with type
     */
    showMessage(message, type) {
        const timestamp = new Date().toLocaleTimeString();
        this.addLog('ui', timestamp, message, type);
        
        // Also show in console
        console.log(`[UI ${timestamp}] ${message}`);
    }
}

// Create global instance
window.UIController = new UIController();