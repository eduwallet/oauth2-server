# HSM Attestation Wallet Demo

A comprehensive browser-based demonstration of hardware-backed JWT attestation authentication, showcasing secure wallet operations with HSM simulation, biometric authentication, and OAuth2 integration.

## 🔐 Security Features

- **Hardware Security Module (HSM) Simulation**: Simulates secure key generation, storage, and cryptographic operations
- **Biometric Authentication**: Multiple biometric types (fingerprint, face, voice recognition)
- **JWT Attestation**: Hardware-backed attestation tokens proving device integrity
- **OAuth2 Integration**: Enhanced OAuth2 flows with attestation-based client authentication
- **Key Attestation**: Cryptographic proof of key hardware backing

## 🚀 Quick Start

1. **Open the Demo**:
   ```bash
   cd /Users/kodde001/Projects/oauth2-server/examples/hsm-attestation-wallet
   python3 -m http.server 8000
   ```
   
   Open http://localhost:8000 in your browser.

2. **Initialize Services**:
   Click "Initialize All" to set up all security services.

3. **Explore Features**:
   - Navigate through different tabs to explore functionality
   - Create attestation tokens
   - Perform biometric authentication

## 📱 User Interface

The demo provides five main sections:

### 1. Overview
- Service status indicators
- System initialization controls
- Real-time activity logs

### 2. HSM Operations
- Key pair generation and management
- Hardware security module operations
- Key attestation certificate creation

### 3. Biometric Authentication
- User enrollment for multiple biometric types
- Authentication testing
- Confidence scoring and validation

### 4. Attestation Service
- JWT attestation token creation
- Token verification and validation
- Hardware-backed claims demonstration

### 5. OAuth2 Integration
- Client registration with attestation
- Authorization code flow with PKCE
- Token exchange with JWT assertions

## 🛠 Technical Architecture

### Core Components

1. **CryptoUtils** (`crypto-utils.js`)
   - Web Crypto API integration
   - JWT handling and validation
   - PKCE implementation
   - Random generation utilities

2. **HSMSimulator** (`hsm-simulator.js`)
   - Hardware Security Module simulation
   - Secure key generation and storage
   - Cryptographic operations
   - Device attestation

3. **BiometricSimulator** (`biometric-simulator.js`)
   - Biometric authentication simulation
   - Multiple authentication factors
   - Confidence scoring
   - User enrollment management

4. **AttestationService** (`attestation-service.js`)
   - JWT attestation token creation
   - Hardware-backed claims
   - Token verification
   - Device integrity validation

5. **OAuth2Client** (`oauth2-client.js`)
   - OAuth2 authorization code flow
   - JWT client assertion authentication
   - PKCE implementation
   - Token management

6. **UIController** (`ui-controller.js`)
   - User interface coordination
   - Real-time status updates
   - Event handling
   - Log management

### Security Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Browser   │    │     HSM      │    │   Biometric     │
│             │    │  Simulator   │    │   Simulator     │
└─────────────┘    └──────────────┘    └─────────────────┘
       │                   │                     │
       │ 1. Generate Keys  │                     │
       ├──────────────────►│                     │
       │                   │                     │
       │ 2. Enroll User    │                     │
       ├─────────────────────────────────────────►│
       │                   │                     │
       │ 3. Create Attestation Token              │
       ├──────────────────►│                     │
       │                   │ 4. Biometric Auth   │
       │                   ├────────────────────►│
       │                   │                     │
```

## 🔧 Configuration

### OAuth2 Server Integration

To integrate with a running OAuth2 server:

1. **Update Configuration** (`static/js/oauth2-client.js`):
   ```javascript
   this.config = {
       serverUrl: 'http://localhost:8080',  // Your OAuth2 server
       clientId: 'hsm-attestation-wallet-demo',
       redirectUri: `${window.location.origin}/callback`,
       scope: 'openid profile email wallet:read wallet:write'
   };
   ```

2. **Register Client**: The demo will automatically register with the OAuth2 server using JWT attestation.

3. **Trust Configuration**: Add the HSM trust anchor to your OAuth2 server configuration.

### HSM Configuration

The HSM simulator can be configured in `hsm-simulator.js`:

```javascript
// Modify security parameters
this.securityLevel = 'hardware';  // hardware, software, tee
this.keySize = 256;              // Key size for EC operations
this.tamperDetection = true;     // Enable tamper detection
```

## 🎮 Demo Scenarios

The demo includes three built-in scenarios accessible via keyboard shortcuts:

- **Ctrl/Cmd + 1**: Quick Start Demo
- **Ctrl/Cmd + 2**: Complete Authentication Flow
- **Ctrl/Cmd + 3**: Security Features Demo
- **Ctrl/Cmd + R**: Reset Demo

### Programmatic Access

```javascript
// Access demo instance
console.log(window.demo.getStatus());

// Run scenarios
await window.demo.runScenario('quickStart');
await window.demo.runScenario('fullFlow');
await window.demo.runScenario('securityDemo');

// Export state for debugging
console.log(window.demo.exportState());
```

## 🧪 Testing

### Manual Testing

1. **Service Initialization**:
   - Click "Initialize All"
   - Verify all status indicators turn green
   - Check logs for successful initialization

2. **Biometric Authentication**:
   - Navigate to Biometric tab
   - Click "Enroll User"
   - Click "Authenticate"
   - Verify successful authentication

3. **Attestation Tokens**:
   - Navigate to Attestation tab
   - Click "Create Attestation"
   - Click "Verify Attestation"
   - Verify token validation

### Browser Developer Tools

Access comprehensive logging in the browser console:

```javascript
// Service status
console.log(demo.services.hsm.getStatus());
console.log(demo.services.biometric.getStatus());
console.log(demo.services.attestation.getStatus());

// Export complete state
console.log(demo.exportState());
```

## 📊 Monitoring

The demo provides real-time monitoring through:

- **Status Indicators**: Visual status for each service
- **Activity Logs**: Real-time operation logging
- **Service Events**: Comprehensive event logging

## 🔍 Debugging

### Common Issues

1. **Services Not Initializing**:
   - Check browser console for errors
   - Ensure all JavaScript files are loaded
   - Verify Web Crypto API availability

2. **Biometric Authentication Failing**:
   - Ensure user is enrolled first
   - Check biometric type compatibility
   - Verify simulator is initialized

3. **OAuth2 Integration Issues**:
   - Verify OAuth2 server is running
   - Check client registration status
   - Validate attestation token creation

### Debug Mode

Enable verbose logging:

```javascript
// Enable debug mode
window.DEBUG = true;

// View detailed logs
demo.services.hsm.enableDebugLogging();
demo.services.attestation.enableVerboseLogging();
```

## 🚀 Production Deployment

For production deployment:

1. **Replace Simulators**: Replace HSM and biometric simulators with actual hardware integrations
2. **Security Hardening**: Implement proper certificate validation and trust chains
3. **Error Handling**: Add comprehensive error handling and recovery
4. **Logging**: Implement secure audit logging
5. **Rate Limiting**: Add rate limiting for sensitive operations

## 📚 Educational Use

This demo is designed for educational purposes to demonstrate:

- Hardware-backed security concepts
- JWT attestation token structure
- OAuth2 enhancement with attestation
- Biometric authentication integration

## 🤝 Contributing

This demo is part of a larger OAuth2 server project. Contributions should focus on:

- Enhanced security demonstrations
- Additional biometric types
- Improved user interface
- Better error handling
- Documentation improvements

## 📄 License

This demo is provided as educational material. See the main project license for usage terms.

## 🔗 Related Resources

- [OAuth2 Server Implementation](../../)
- [JWT Attestation Specification](https://tools.ietf.org/html/draft-ietf-oauth-attestation-based-client-auth)
- [Web Crypto API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [HSM Best Practices](https://csrc.nist.gov/publications/detail/fips/140/2/final)