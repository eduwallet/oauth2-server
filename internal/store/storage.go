package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"reflect"
	"strings"
	"time"

	"oauth2-server/pkg/config"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// getRequestFields uses reflection to get fields from a fosite.Requester to avoid method calls that may do type assertions
func getRequestFields(request fosite.Requester) map[string]interface{} {
	fields := make(map[string]interface{})

	v := reflect.ValueOf(request)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if !v.IsValid() {
		return fields
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldName := t.Field(i).Name

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		switch fieldName {
		case "ID":
			if field.Kind() == reflect.String {
				fields["id"] = field.String()
			}
		case "RequestedAt":
			if field.Type() == reflect.TypeOf(time.Time{}) {
				fields["requested_at"] = field.Interface()
			}
		case "GrantedScopes":
			if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String {
				fields["granted_scopes"] = field.Interface()
			}
		case "RequestedScopes":
			if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String {
				fields["requested_scopes"] = field.Interface()
			}
		case "GrantedAudience":
			if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String {
				fields["granted_audience"] = field.Interface()
			}
		case "RequestedAudience":
			if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String {
				fields["requested_audience"] = field.Interface()
			}
		case "Form":
			if field.Type() == reflect.TypeOf(url.Values{}) {
				fields["form"] = field.Interface()
			}
		case "Session":
			if !field.IsNil() {
				sessionData, err := json.Marshal(field.Interface())
				if err == nil {
					var sessionMap map[string]interface{}
					if json.Unmarshal(sessionData, &sessionMap) == nil {
						fields["session"] = sessionMap
					}
				}
			}
		case "Client":
			if !field.IsNil() {
				client := field.Interface().(fosite.Client)
				fields["_client_id"] = client.GetID()
				clientData := map[string]interface{}{
					"type":           "DefaultClient",
					"id":             client.GetID(),
					"hashed_secret":  string(client.GetHashedSecret()),
					"redirect_uris":  client.GetRedirectURIs(),
					"grant_types":    client.GetGrantTypes(),
					"response_types": client.GetResponseTypes(),
					"scopes":         client.GetScopes(),
					"audience":       client.GetAudience(),
					"public":         client.IsPublic(),
				}
				fields["client"] = clientData
			}
		}
	}

	return fields
}

// RequestWithClientID stores a fosite.Requester with client ID stored separately for proper JSON marshaling
type RequestWithClientID struct {
	Request       *fosite.Request       `json:"-"`
	AccessRequest *fosite.AccessRequest `json:"-"`
	ClientID      string                `json:"_client_id"`
	Type          string                `json:"_type"`
}

// DeviceRequestWithClientID stores a fosite.DeviceRequester with client ID stored separately for proper JSON marshaling
type DeviceRequestWithClientID struct {
	DeviceRequest *fosite.DeviceRequest `json:"-"`
	ClientID      string                `json:"_client_id"`
	Type          string                `json:"_type"`
}

// GetClient returns the client
func (r *DeviceRequestWithClientID) GetClient() fosite.Client {
	if r.DeviceRequest != nil && r.DeviceRequest.Request.Client != nil {
		return r.DeviceRequest.Request.Client
	}
	return nil
}

// GetRequestedScopes returns the requested scopes
func (r *DeviceRequestWithClientID) GetRequestedScopes() fosite.Arguments {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetRequestedScopes()
	}
	return nil
}

// GetGrantedScopes returns the granted scopes
func (r *DeviceRequestWithClientID) GetGrantedScopes() fosite.Arguments {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetGrantedScopes()
	}
	return nil
}

// GetRequestedAudience returns the requested audience
func (r *DeviceRequestWithClientID) GetRequestedAudience() fosite.Arguments {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetRequestedAudience()
	}
	return nil
}

// GetGrantedAudience returns the granted audience
func (r *DeviceRequestWithClientID) GetGrantedAudience() fosite.Arguments {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetGrantedAudience()
	}
	return nil
}

// GetSession returns the session
func (r *DeviceRequestWithClientID) GetSession() fosite.Session {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetSession()
	}
	return nil
}

// SetSession sets the session
func (r *DeviceRequestWithClientID) SetSession(session fosite.Session) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.SetSession(session)
	}
}

// GetID returns the request ID
func (r *DeviceRequestWithClientID) GetID() string {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetID()
	}
	return ""
}

// GetRequestedAt returns the requested at time
func (r *DeviceRequestWithClientID) GetRequestedAt() time.Time {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetRequestedAt()
	}
	return time.Time{}
}

// GetUserCodeState returns the user code state
func (r *DeviceRequestWithClientID) GetUserCodeState() fosite.UserCodeState {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetUserCodeState()
	}
	return fosite.UserCodeUnused
}

// SetUserCodeState sets the user code state
func (r *DeviceRequestWithClientID) SetUserCodeState(state fosite.UserCodeState) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.SetUserCodeState(state)
	}
}

// GetScopes returns the scopes (alias for GetGrantedScopes)
func (r *DeviceRequestWithClientID) GetScopes() fosite.Arguments {
	return r.GetGrantedScopes()
}

// GetAudience returns the audience (alias for GetGrantedAudience)
func (r *DeviceRequestWithClientID) GetAudience() fosite.Arguments {
	return r.GetGrantedAudience()
}

// GrantScope grants a scope
func (r *DeviceRequestWithClientID) GrantScope(scope string) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.GrantScope(scope)
	}
}

// GrantAudience grants an audience
func (r *DeviceRequestWithClientID) GrantAudience(audience string) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.GrantAudience(audience)
	}
}

// GetRequestForm returns the request form
func (r *DeviceRequestWithClientID) GetRequestForm() url.Values {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.GetRequestForm()
	}
	return nil
}

// Merge merges another requester
func (r *DeviceRequestWithClientID) Merge(requester fosite.Requester) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.Merge(requester)
	}
}

// Sanitize sanitizes the request
func (r *DeviceRequestWithClientID) Sanitize(allowedParameters []string) fosite.Requester {
	if r.DeviceRequest != nil {
		return r.DeviceRequest.Sanitize(allowedParameters)
	}
	return nil
}

// AppendRequestedScope appends a requested scope
func (r *DeviceRequestWithClientID) AppendRequestedScope(scope string) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.AppendRequestedScope(scope)
	}
}

// SetRequestedAudience sets the requested audience
func (r *DeviceRequestWithClientID) SetRequestedAudience(audience fosite.Arguments) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.SetRequestedAudience(audience)
	}
}

// SetID sets the request ID
func (r *DeviceRequestWithClientID) SetID(id string) {
	if r.DeviceRequest != nil {
		r.DeviceRequest.SetID(id)
	}
}

// MarshalJSON implements custom JSON marshaling for DeviceRequestWithClientID
func (r *DeviceRequestWithClientID) MarshalJSON() ([]byte, error) {
	if r.DeviceRequest == nil {
		return nil, fmt.Errorf("no device request to marshal")
	}

	// Start with the embedded Request marshaling
	requestData, err := json.Marshal(r.DeviceRequest.Request)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(requestData, &raw); err != nil {
		return nil, err
	}

	// Add device-specific fields
	raw["user_code_state"] = r.DeviceRequest.UserCodeState
	raw["_client_id"] = r.ClientID
	raw["_type"] = r.Type

	// Handle the client field specially - include type information
	if client := r.GetClient(); client != nil {
		clientData := map[string]interface{}{
			"type":           "DefaultClient",
			"id":             r.ClientID,
			"hashed_secret":  string(client.GetHashedSecret()),
			"redirect_uris":  client.GetRedirectURIs(),
			"grant_types":    client.GetGrantTypes(),
			"response_types": client.GetResponseTypes(),
			"scopes":         client.GetScopes(),
			"audience":       client.GetAudience(),
			"public":         client.IsPublic(),
		}
		raw["client"] = clientData
	}

	// Handle the session field - marshal it separately
	if session := r.GetSession(); session != nil {
		sessionData, err := json.Marshal(session)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal session: %w", err)
		}
		var sessionMap map[string]interface{}
		if json.Unmarshal(sessionData, &sessionMap) == nil {
			raw["session"] = sessionMap
		}
	}

	return json.Marshal(raw)
}

// UnmarshalJSON implements custom JSON unmarshaling for DeviceRequestWithClientID
func (r *DeviceRequestWithClientID) UnmarshalJSON(data []byte) error {
	// First unmarshal into a map
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Extract our fields
	if clientID, ok := raw["_client_id"].(string); ok {
		r.ClientID = clientID
		delete(raw, "_client_id")
	}
	if reqType, ok := raw["_type"].(string); ok {
		r.Type = reqType
		delete(raw, "_type")
	}

	// Extract user code state
	var userCodeState fosite.UserCodeState
	if ucs, ok := raw["user_code_state"].(float64); ok {
		userCodeState = fosite.UserCodeState(int16(ucs))
		delete(raw, "user_code_state")
	}

	// Handle the client field - extract and unmarshal it separately
	if clientData, exists := raw["client"]; exists && clientData != nil {
		delete(raw, "client")
	}

	// Handle the session field - extract and unmarshal it as the correct concrete type
	if sessionData, exists := raw["session"]; exists && sessionData != nil {
		sessionBytes, err := json.Marshal(sessionData)
		if err != nil {
			return fmt.Errorf("failed to marshal session data: %w", err)
		}
		var session openid.DefaultSession
		if err := json.Unmarshal(sessionBytes, &session); err != nil {
			return fmt.Errorf("failed to unmarshal session: %w", err)
		}
		delete(raw, "session")

		// Now unmarshal the modified data into the Request
		modifiedData, err := json.Marshal(raw)
		if err != nil {
			return err
		}

		r.DeviceRequest = &fosite.DeviceRequest{}
		if err := json.Unmarshal(modifiedData, &r.DeviceRequest.Request); err != nil {
			return err
		}
		r.DeviceRequest.UserCodeState = userCodeState
		r.DeviceRequest.Request.Session = &session
	} else {
		// No session data, just unmarshal the request
		modifiedData, err := json.Marshal(raw)
		if err != nil {
			return err
		}

		r.DeviceRequest = &fosite.DeviceRequest{}
		if err := json.Unmarshal(modifiedData, &r.DeviceRequest.Request); err != nil {
			return err
		}
		r.DeviceRequest.UserCodeState = userCodeState
	}

	return nil
}

// MarshalDeviceRequestWithClientID marshals a fosite.DeviceRequester with client ID stored separately
func MarshalDeviceRequestWithClientID(request fosite.DeviceRequester) ([]byte, error) {
	raw := make(map[string]interface{})

	// Get the underlying request data
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(requestData, &raw); err != nil {
		return nil, err
	}

	// Add type information
	raw["_type"] = "DeviceRequest"
	if client := request.GetClient(); client != nil {
		raw["_client_id"] = client.GetID()
	}

	return json.Marshal(raw)
}

// UnmarshalDeviceRequestWithClientID unmarshals a fosite.DeviceRequester with client looked up by ID
func (s *SQLiteStore) UnmarshalDeviceRequestWithClientID(data []byte) (fosite.DeviceRequester, error) {
	log.Printf("🔍 UnmarshalDeviceRequestWithClientID: starting unmarshal of data (length: %d): %s", len(data), string(data))

	var wrapper DeviceRequestWithClientID
	if err := json.Unmarshal(data, &wrapper); err != nil {
		log.Printf("❌ UnmarshalDeviceRequestWithClientID: failed to unmarshal wrapper: %v", err)
		return nil, err
	}

	log.Printf("🔍 UnmarshalDeviceRequestWithClientID: wrapper type: %s, clientID: %s", wrapper.Type, wrapper.ClientID)

	if wrapper.DeviceRequest == nil {
		return nil, fmt.Errorf("DeviceRequest is nil")
	}

	// Set client if we have a client ID
	if wrapper.ClientID != "" {
		client, err := s.GetClient(context.Background(), wrapper.ClientID)
		if err != nil {
			log.Printf("❌ UnmarshalDeviceRequestWithClientID: GetClient error for %s: %v", wrapper.ClientID, err)
			return nil, err
		}
		wrapper.DeviceRequest.Request.Client = client
		log.Printf("✅ UnmarshalDeviceRequestWithClientID: set client %s on device request", wrapper.ClientID)
	}

	log.Printf("✅ UnmarshalDeviceRequestWithClientID: successfully unmarshaled device request")
	return wrapper.DeviceRequest, nil
}

// GetClient returns the client
func (r *RequestWithClientID) GetClient() fosite.Client {
	if r.Request != nil {
		return r.Request.GetClient()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetClient()
	}
	return nil
}

// GetRequestedScopes returns the requested scopes
func (r *RequestWithClientID) GetRequestedScopes() fosite.Arguments {
	if r.Request != nil {
		return r.Request.GetRequestedScopes()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetRequestedScopes()
	}
	return nil
}

// GetGrantedScopes returns the granted scopes
func (r *RequestWithClientID) GetGrantedScopes() fosite.Arguments {
	if r.Request != nil {
		return r.Request.GetGrantedScopes()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetGrantedScopes()
	}
	return nil
}

// GetRequestedAudience returns the requested audience
func (r *RequestWithClientID) GetRequestedAudience() fosite.Arguments {
	if r.Request != nil {
		return r.Request.GetRequestedAudience()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetRequestedAudience()
	}
	return nil
}

// GetGrantedAudience returns the granted audience
func (r *RequestWithClientID) GetGrantedAudience() fosite.Arguments {
	if r.Request != nil {
		return r.Request.GetGrantedAudience()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetGrantedAudience()
	}
	return nil
}

// GetSession returns the session
func (r *RequestWithClientID) GetSession() fosite.Session {
	if r.Request != nil {
		return r.Request.GetSession()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetSession()
	}
	return nil
}

// SetSession sets the session
func (r *RequestWithClientID) SetSession(session fosite.Session) {
	if r.Request != nil {
		r.Request.SetSession(session)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.SetSession(session)
	}
}

// GetID returns the request ID
func (r *RequestWithClientID) GetID() string {
	if r.Request != nil {
		return r.Request.GetID()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetID()
	}
	return ""
}

// GetRequestedAt returns the requested at time
func (r *RequestWithClientID) GetRequestedAt() time.Time {
	if r.Request != nil {
		return r.Request.GetRequestedAt()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetRequestedAt()
	}
	return time.Time{}
}

// GetScopes returns the scopes (alias for GetGrantedScopes)
func (r *RequestWithClientID) GetScopes() fosite.Arguments {
	return r.GetGrantedScopes()
}

// GetAudience returns the audience (alias for GetGrantedAudience)
func (r *RequestWithClientID) GetAudience() fosite.Arguments {
	return r.GetGrantedAudience()
}

// GrantScope grants a scope
func (r *RequestWithClientID) GrantScope(scope string) {
	if r.Request != nil {
		r.Request.GrantScope(scope)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.GrantScope(scope)
	}
}

// GrantAudience grants an audience
func (r *RequestWithClientID) GrantAudience(audience string) {
	if r.Request != nil {
		r.Request.GrantAudience(audience)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.GrantAudience(audience)
	}
}

// GetRequestForm returns the request form
func (r *RequestWithClientID) GetRequestForm() url.Values {
	if r.Request != nil {
		return r.Request.GetRequestForm()
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.GetRequestForm()
	}
	return nil
}

// Merge merges another requester
func (r *RequestWithClientID) Merge(requester fosite.Requester) {
	if r.Request != nil {
		r.Request.Merge(requester)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.Merge(requester)
	}
}

// Sanitize sanitizes the request
func (r *RequestWithClientID) Sanitize(allowedParameters []string) fosite.Requester {
	if r.Request != nil {
		return r.Request.Sanitize(allowedParameters)
	}
	if r.AccessRequest != nil {
		return r.AccessRequest.Sanitize(allowedParameters)
	}
	return nil
}

// AppendRequestedScope appends a requested scope
func (r *RequestWithClientID) AppendRequestedScope(scope string) {
	if r.Request != nil {
		r.Request.AppendRequestedScope(scope)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.AppendRequestedScope(scope)
	}
}

// SetRequestedAudience sets the requested audience
func (r *RequestWithClientID) SetRequestedAudience(audience fosite.Arguments) {
	if r.Request != nil {
		r.Request.SetRequestedAudience(audience)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.SetRequestedAudience(audience)
	}
}

// SetID sets the request ID
func (r *RequestWithClientID) SetID(id string) {
	if r.Request != nil {
		r.Request.SetID(id)
	}
	if r.AccessRequest != nil {
		r.AccessRequest.SetID(id)
	}
}

// MarshalJSON implements custom JSON marshaling for RequestWithClientID
func (r *RequestWithClientID) MarshalJSON() ([]byte, error) {
	var raw map[string]interface{}

	if r.Request != nil {
		// Use json.Marshal for Request
		requestData, err := json.Marshal(r.Request)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(requestData, &raw); err != nil {
			return nil, err
		}
	} else if r.AccessRequest != nil {
		// Manually create JSON for AccessRequest to avoid marshaling issues
		raw = make(map[string]interface{})

		// Add basic fields
		raw["id"] = r.AccessRequest.GetID()
		raw["requested_at"] = r.AccessRequest.GetRequestedAt()

		// Add scopes
		if scopes := r.AccessRequest.GetGrantedScopes(); scopes != nil {
			raw["granted_scopes"] = scopes
		}
		if scopes := r.AccessRequest.GetRequestedScopes(); scopes != nil {
			raw["requested_scopes"] = scopes
		}

		// Add audience
		if audience := r.AccessRequest.GetGrantedAudience(); audience != nil {
			raw["granted_audience"] = audience
		}
		if audience := r.AccessRequest.GetRequestedAudience(); audience != nil {
			raw["requested_audience"] = audience
		}

		// Add form data
		if form := r.AccessRequest.GetRequestForm(); form != nil {
			raw["form"] = form
		}
	} else {
		return nil, fmt.Errorf("no request to marshal")
	}

	// Add our fields
	raw["_client_id"] = r.ClientID
	raw["_type"] = r.Type

	// Handle the client field specially - include type information
	if client := r.GetClient(); client != nil {
		clientData := map[string]interface{}{
			"type":           "DefaultClient",
			"id":             r.ClientID,
			"hashed_secret":  string(client.GetHashedSecret()),
			"redirect_uris":  client.GetRedirectURIs(),
			"grant_types":    client.GetGrantTypes(),
			"response_types": client.GetResponseTypes(),
			"scopes":         client.GetScopes(),
			"audience":       client.GetAudience(),
			"public":         client.IsPublic(),
		}
		raw["client"] = clientData
	}

	// Handle the session field - marshal it separately
	if session := r.GetSession(); session != nil {
		sessionData, err := json.Marshal(session)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal session: %w", err)
		}
		var sessionMap map[string]interface{}
		if err := json.Unmarshal(sessionData, &sessionMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal session for map: %w", err)
		}
		raw["session"] = sessionMap
	}

	return json.Marshal(raw)
}

// UnmarshalJSON implements custom JSON unmarshaling for RequestWithClientID
func (r *RequestWithClientID) UnmarshalJSON(data []byte) error {
	// First unmarshal into a map
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Extract our fields
	if clientID, ok := raw["_client_id"].(string); ok {
		r.ClientID = clientID
		delete(raw, "_client_id")
	}
	if reqType, ok := raw["_type"].(string); ok {
		r.Type = reqType
		delete(raw, "_type")
	}

	// Handle the client field - extract and unmarshal it separately
	if clientData, exists := raw["client"]; exists && clientData != nil {
		clientBytes, err := json.Marshal(clientData)
		if err != nil {
			return fmt.Errorf("failed to marshal client data: %w", err)
		}
		var client fosite.DefaultClient
		if err := json.Unmarshal(clientBytes, &client); err != nil {
			return fmt.Errorf("failed to unmarshal client: %w", err)
		}
		// Don't set client here - it will be set later after lookup
		delete(raw, "client")
	}

	// Handle the session field - extract and unmarshal it as the correct concrete type
	if sessionData, exists := raw["session"]; exists && sessionData != nil {
		sessionBytes, err := json.Marshal(sessionData)
		if err != nil {
			return fmt.Errorf("failed to marshal session data: %w", err)
		}

		// Try to unmarshal as openid.DefaultSession first (most common)
		var session openid.DefaultSession
		if err := json.Unmarshal(sessionBytes, &session); err != nil {
			// If that fails, try TokenExchangeSession
			var tokenExchangeSession rfc8693.TokenExchangeSession
			if err := json.Unmarshal(sessionBytes, &tokenExchangeSession); err != nil {
				// If that fails, try fosite.DefaultSession
				var defaultSession fosite.DefaultSession
				if err := json.Unmarshal(sessionBytes, &defaultSession); err != nil {
					return fmt.Errorf("failed to unmarshal session as any known type: %w", err)
				}
				// Store default session to be set later
				delete(raw, "session")

				// Now unmarshal the modified data into the appropriate request type
				modifiedData, err := json.Marshal(raw)
				if err != nil {
					return err
				}

				switch r.Type {
				case "Request":
					r.Request = &fosite.Request{}
					if err := json.Unmarshal(modifiedData, r.Request); err != nil {
						return err
					}
					r.Request.Session = &defaultSession
				case "AccessRequest":
					r.AccessRequest = &fosite.AccessRequest{}
					if err := json.Unmarshal(modifiedData, r.AccessRequest); err != nil {
						return err
					}
					r.AccessRequest.Session = &defaultSession
				default:
					// Default to Request
					r.Request = &fosite.Request{}
					if err := json.Unmarshal(modifiedData, r.Request); err != nil {
						return err
					}
					r.Request.Session = &defaultSession
				}
			} else {
				// Store token exchange session to be set later
				delete(raw, "session")

				// Now unmarshal the modified data into the appropriate request type
				modifiedData, err := json.Marshal(raw)
				if err != nil {
					return err
				}

				switch r.Type {
				case "Request":
					r.Request = &fosite.Request{}
					if err := json.Unmarshal(modifiedData, r.Request); err != nil {
						return err
					}
					r.Request.Session = &tokenExchangeSession
				case "AccessRequest":
					r.AccessRequest = &fosite.AccessRequest{}
					if err := json.Unmarshal(modifiedData, r.AccessRequest); err != nil {
						return err
					}
					r.AccessRequest.Session = &tokenExchangeSession
				default:
					// Default to Request
					r.Request = &fosite.Request{}
					if err := json.Unmarshal(modifiedData, r.Request); err != nil {
						return err
					}
					r.Request.Session = &tokenExchangeSession
				}
			}
		} else {
			// Store openid session to be set later
			delete(raw, "session")

			// Now unmarshal the modified data into the appropriate request type
			modifiedData, err := json.Marshal(raw)
			if err != nil {
				return err
			}

			switch r.Type {
			case "Request":
				r.Request = &fosite.Request{}
				if err := json.Unmarshal(modifiedData, r.Request); err != nil {
					return err
				}
				r.Request.Session = &session
			case "AccessRequest":
				r.AccessRequest = &fosite.AccessRequest{}
				if err := json.Unmarshal(modifiedData, r.AccessRequest); err != nil {
					return err
				}
				r.AccessRequest.Session = &session
			default:
				// Default to Request
				r.Request = &fosite.Request{}
				if err := json.Unmarshal(modifiedData, r.Request); err != nil {
					return err
				}
				r.Request.Session = &session
			}
		}
	} else {
		// No session data, just unmarshal the request
		modifiedData, err := json.Marshal(raw)
		if err != nil {
			return err
		}

		switch r.Type {
		case "Request":
			r.Request = &fosite.Request{}
			if err := json.Unmarshal(modifiedData, r.Request); err != nil {
				return err
			}
		case "AccessRequest":
			r.AccessRequest = &fosite.AccessRequest{}
			if err := json.Unmarshal(modifiedData, r.AccessRequest); err != nil {
				return err
			}
		default:
			// Default to Request
			r.Request = &fosite.Request{}
			if err := json.Unmarshal(modifiedData, r.Request); err != nil {
				return err
			}
		}
	}

	return nil
}

// MarshalRequestWithClientID marshals a fosite.Requester with client ID stored separately
func MarshalRequestWithClientID(request fosite.Requester) ([]byte, error) {
	raw := getRequestFields(request)

	// Determine type
	if _, ok := request.(*fosite.Request); ok {
		raw["_type"] = "Request"
	} else if _, ok := request.(*fosite.AccessRequest); ok {
		raw["_type"] = "AccessRequest"
	} else {
		raw["_type"] = "Unknown"
	}

	return json.Marshal(raw)
}

// UnmarshalRequestWithClientID unmarshals a fosite.Requester with client looked up by ID
func (s *SQLiteStore) UnmarshalRequestWithClientID(data []byte) (fosite.Requester, error) {
	// log.Printf("🔍 UnmarshalRequestWithClientID: starting unmarshal of data (length: %d): %s", len(data), string(data))

	var wrapper RequestWithClientID
	if err := json.Unmarshal(data, &wrapper); err != nil {
		log.Printf("❌ UnmarshalRequestWithClientID: failed to unmarshal wrapper: %v", err)
		return nil, err
	}

	//log.Printf("🔍 UnmarshalRequestWithClientID: wrapper type: %s, clientID: %s", wrapper.Type, wrapper.ClientID)

	var request fosite.Requester
	switch wrapper.Type {
	case "Request":
		if wrapper.Request != nil {
			request = wrapper.Request
		} else {
			return nil, fmt.Errorf("Request is nil")
		}
	case "AccessRequest":
		if wrapper.AccessRequest != nil {
			request = wrapper.AccessRequest
		} else {
			return nil, fmt.Errorf("AccessRequest is nil")
		}
	default:
		return nil, fmt.Errorf("unknown type: %s", wrapper.Type)
	}

	// Set client if we have a client ID
	if wrapper.ClientID != "" {
		client, err := s.GetClient(context.Background(), wrapper.ClientID)
		if err != nil {
			log.Printf("❌ UnmarshalRequestWithClientID: GetClient error for %s: %v", wrapper.ClientID, err)
			return nil, err
		}
		// Set client on the request
		switch req := request.(type) {
		case *fosite.Request:
			req.Client = client
		case *fosite.AccessRequest:
			req.Client = client
		}
		log.Printf("✅ UnmarshalRequestWithClientID: set client %s on request", wrapper.ClientID)
	}

	log.Printf("✅ UnmarshalRequestWithClientID: successfully unmarshaled request")
	return request, nil
}

// Storage interface that both MemoryStore and SQLiteStore implement
type Storage interface {
	// Client storage methods
	GetClient(ctx context.Context, id string) (fosite.Client, error)
	CreateClient(ctx context.Context, client fosite.Client) error
	UpdateClient(ctx context.Context, id string, client fosite.Client) error
	DeleteClient(ctx context.Context, id string) error

	// User storage methods
	GetUser(ctx context.Context, id string) (*storage.MemoryUserRelation, error)

	// Token storage methods
	CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error
	GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	DeleteAccessTokenSession(ctx context.Context, signature string) error
	CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error
	GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	DeleteRefreshTokenSession(ctx context.Context, signature string) error
	RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error
	RevokeAccessToken(ctx context.Context, requestID string) error
	RevokeRefreshToken(ctx context.Context, requestID string) error
	CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error
	GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error)
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) error

	// PKCE methods
	CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error
	GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error)
	DeletePKCERequestSession(ctx context.Context, code string) error

	// Client Assertion JWT methods
	ClientAssertionJWTValid(ctx context.Context, jti string) error
	SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error

	// Device authorization methods
	GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error)
	CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error
	UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error
	InvalidateDeviceCodeSession(ctx context.Context, signature string) error
	GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error)
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (fosite.DeviceRequester, string, error)
	CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error

	// Statistics methods
	GetClientCount() (int, error)
	GetUserCount() (int, error)
	GetAccessTokenCount() (int, error)
	GetRefreshTokenCount() (int, error)

	// Secure client data storage methods
	StoreClientSecret(ctx context.Context, clientID string, encryptedSecret string) error
	GetClientSecret(ctx context.Context, clientID string) (string, error)
	StoreAttestationConfig(ctx context.Context, clientID string, config *config.ClientAttestationConfig) error
	GetAttestationConfig(ctx context.Context, clientID string) (*config.ClientAttestationConfig, error)

	// Trust anchor storage methods
	StoreTrustAnchor(ctx context.Context, name string, certificateData []byte) error
	GetTrustAnchor(ctx context.Context, name string) ([]byte, error)
	ListTrustAnchors(ctx context.Context) ([]string, error)
	DeleteTrustAnchor(ctx context.Context, name string) error

	// Upstream token mapping methods for proxy mode
	StoreUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string, upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64) error
	GetUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) (upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64, err error)
	DeleteUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) error
}

// MemoryStoreWrapper wraps fosite's MemoryStore to implement our Storage interface
type MemoryStoreWrapper struct {
	*storage.MemoryStore
	clientSecrets         map[string]string
	attestationConfigs    map[string]*config.ClientAttestationConfig
	trustAnchors          map[string][]byte
	upstreamTokenMappings map[string]*UpstreamTokenMapping
	logger                *logrus.Logger
}

// UpstreamTokenMapping stores upstream token information for proxy tokens
type UpstreamTokenMapping struct {
	UpstreamAccessToken  string
	UpstreamRefreshToken string
	UpstreamTokenType    string
	UpstreamExpiresIn    int64
	CreatedAt            time.Time
}

// NewMemoryStoreWrapper creates a new MemoryStoreWrapper with initialized maps
func NewMemoryStoreWrapper(memoryStore *storage.MemoryStore, logger *logrus.Logger) *MemoryStoreWrapper {
	return &MemoryStoreWrapper{
		MemoryStore:           memoryStore,
		clientSecrets:         make(map[string]string),
		attestationConfigs:    make(map[string]*config.ClientAttestationConfig),
		trustAnchors:          make(map[string][]byte),
		upstreamTokenMappings: make(map[string]*UpstreamTokenMapping),
		logger:                logger,
	}
}

// Client management methods
func (m *MemoryStoreWrapper) CreateClient(ctx context.Context, client fosite.Client) error {
	m.MemoryStore.Clients[client.GetID()] = client
	return nil
}

func (m *MemoryStoreWrapper) UpdateClient(ctx context.Context, id string, client fosite.Client) error {
	m.MemoryStore.Clients[id] = client
	return nil
}

func (m *MemoryStoreWrapper) DeleteClient(ctx context.Context, id string) error {
	delete(m.MemoryStore.Clients, id)
	return nil
}

// Add GetUser method that MemoryStore has but our interface requires
func (m *MemoryStoreWrapper) GetUser(ctx context.Context, id string) (*storage.MemoryUserRelation, error) {
	user, exists := m.MemoryStore.Users[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

// Implement missing methods that MemoryStore doesn't have
func (m *MemoryStoreWrapper) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return m.MemoryStore.CreateAccessTokenSession(ctx, signature, request)
}

func (m *MemoryStoreWrapper) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error {
	return m.MemoryStore.CreateRefreshTokenSession(ctx, signature, accessTokenSignature, request)
}

func (m *MemoryStoreWrapper) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return m.MemoryStore.CreateAuthorizeCodeSession(ctx, code, request)
}

func (m *MemoryStoreWrapper) CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error {
	return m.MemoryStore.CreatePKCERequestSession(ctx, code, request)
}

// Device authorization methods
func (m *MemoryStoreWrapper) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error) {
	return m.MemoryStore.GetDeviceCodeSession(ctx, deviceCode, session)
}

func (m *MemoryStoreWrapper) CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	// MemoryStore uses DeviceAuths map directly
	if deviceReq, ok := request.(fosite.DeviceRequester); ok {
		m.MemoryStore.DeviceAuths[deviceCode] = deviceReq
		return nil
	}
	return fmt.Errorf("request is not a DeviceRequester")
}

func (m *MemoryStoreWrapper) UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	if deviceReq, ok := request.(fosite.DeviceRequester); ok {
		m.MemoryStore.DeviceAuths[deviceCode] = deviceReq
		return nil
	}
	return fmt.Errorf("request is not a DeviceRequester")
}

func (m *MemoryStoreWrapper) InvalidateDeviceCodeSession(ctx context.Context, signature string) error {
	return m.MemoryStore.InvalidateDeviceCodeSession(ctx, signature)
}

func (m *MemoryStoreWrapper) GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error) {
	pending := make(map[string]fosite.Requester)
	for deviceCode, auth := range m.MemoryStore.DeviceAuths {
		// Check if it's still pending (no session or empty username)
		session := auth.GetSession()
		if session == nil || session.GetUsername() == "" {
			pending[deviceCode] = auth
		}
	}
	return pending, nil
}

func (m *MemoryStoreWrapper) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (fosite.DeviceRequester, string, error) {
	// In memory store, we need to search through all device auths to find one with matching user code
	// This is inefficient but works for the memory store
	for deviceCode, auth := range m.MemoryStore.DeviceAuths {
		// We can't easily get the user code from the device auth in memory store
		// For now, return the first pending auth (same as before)
		session := auth.GetSession()
		if session == nil || session.GetUsername() == "" {
			return auth, deviceCode, nil
		}
	}
	return nil, "", fmt.Errorf("device authorization not found for user code: %s", userCode)
}

func (m *MemoryStoreWrapper) CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error {
	return m.MemoryStore.CreateDeviceAuthSession(ctx, deviceCodeSignature, userCodeSignature, request)
}

// Statistics methods
func (m *MemoryStoreWrapper) GetClientCount() (int, error) {
	return len(m.MemoryStore.Clients), nil
}

func (m *MemoryStoreWrapper) GetUserCount() (int, error) {
	return len(m.MemoryStore.Users), nil
}

func (m *MemoryStoreWrapper) GetAccessTokenCount() (int, error) {
	return len(m.MemoryStore.AccessTokens), nil
}

func (m *MemoryStoreWrapper) GetRefreshTokenCount() (int, error) {
	return len(m.MemoryStore.RefreshTokens), nil
}

// Secure client data storage methods (for memory store, we store in memory but warn about persistence)
func (m *MemoryStoreWrapper) StoreClientSecret(ctx context.Context, clientID string, encryptedSecret string) error {
	m.clientSecrets[clientID] = encryptedSecret
	m.logger.Warnf("⚠️  [MEMORY STORE] Client secret stored in memory for client %s - this will be lost on restart", clientID)
	return nil
}

func (m *MemoryStoreWrapper) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	secret, exists := m.clientSecrets[clientID]
	if !exists {
		return "", fmt.Errorf("client secret not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved client secret from memory for client %s - this data is not persistent", clientID)
	return secret, nil
}

func (m *MemoryStoreWrapper) StoreAttestationConfig(ctx context.Context, clientID string, config *config.ClientAttestationConfig) error {
	m.attestationConfigs[clientID] = config
	m.logger.Warnf("⚠️  [MEMORY STORE] Attestation config stored in memory for client %s - this will be lost on restart", clientID)
	return nil
}

func (m *MemoryStoreWrapper) GetAttestationConfig(ctx context.Context, clientID string) (*config.ClientAttestationConfig, error) {
	config, exists := m.attestationConfigs[clientID]
	if !exists {
		return nil, fmt.Errorf("attestation config not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved attestation config from memory for client %s - this data is not persistent", clientID)
	return config, nil
}

// Trust anchor storage methods
func (m *MemoryStoreWrapper) StoreTrustAnchor(ctx context.Context, name string, certificateData []byte) error {
	m.trustAnchors[name] = certificateData
	m.logger.Warnf("⚠️  [MEMORY STORE] Trust anchor stored in memory for %s - this will be lost on restart", name)
	return nil
}

func (m *MemoryStoreWrapper) GetTrustAnchor(ctx context.Context, name string) ([]byte, error) {
	data, exists := m.trustAnchors[name]
	if !exists {
		return nil, fmt.Errorf("trust anchor not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved trust anchor from memory for %s - this data is not persistent", name)
	return data, nil
}

func (m *MemoryStoreWrapper) ListTrustAnchors(ctx context.Context) ([]string, error) {
	names := make([]string, 0, len(m.trustAnchors))
	for name := range m.trustAnchors {
		names = append(names, name)
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Listed trust anchors from memory - this data is not persistent")
	return names, nil
}

func (m *MemoryStoreWrapper) DeleteTrustAnchor(ctx context.Context, name string) error {
	if _, exists := m.trustAnchors[name]; !exists {
		return fmt.Errorf("trust anchor not found")
	}
	delete(m.trustAnchors, name)
	m.logger.Warnf("⚠️  [MEMORY STORE] Trust anchor deleted from memory for %s - this data is not persistent", name)
	return nil
}

// Upstream token mapping methods for proxy mode
func (m *MemoryStoreWrapper) StoreUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string, upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64) error {
	m.upstreamTokenMappings[proxyTokenSignature] = &UpstreamTokenMapping{
		UpstreamAccessToken:  upstreamAccessToken,
		UpstreamRefreshToken: upstreamRefreshToken,
		UpstreamTokenType:    upstreamTokenType,
		UpstreamExpiresIn:    upstreamExpiresIn,
		CreatedAt:            time.Now(),
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Upstream token mapping stored in memory for proxy token %s - this will be lost on restart", proxyTokenSignature)
	return nil
}

func (m *MemoryStoreWrapper) GetUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) (upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64, err error) {
	mapping, exists := m.upstreamTokenMappings[proxyTokenSignature]
	if !exists {
		return "", "", "", 0, fmt.Errorf("upstream token mapping not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved upstream token mapping from memory for proxy token %s - this data is not persistent", proxyTokenSignature)
	return mapping.UpstreamAccessToken, mapping.UpstreamRefreshToken, mapping.UpstreamTokenType, mapping.UpstreamExpiresIn, nil
}

func (m *MemoryStoreWrapper) DeleteUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) error {
	if _, exists := m.upstreamTokenMappings[proxyTokenSignature]; !exists {
		return fmt.Errorf("upstream token mapping not found")
	}
	delete(m.upstreamTokenMappings, proxyTokenSignature)
	m.logger.Warnf("⚠️  [MEMORY STORE] Upstream token mapping deleted from memory for proxy token %s - this data is not persistent", proxyTokenSignature)
	return nil
}

// SQLiteStore implements Fosite storage interfaces using SQLite
type SQLiteStore struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewSQLiteStore creates a new SQLite store
func NewSQLiteStore(dbPath string, logger *logrus.Logger) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	store := &SQLiteStore{
		db:     db,
		logger: logger,
	}

	if err := store.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return store, nil
}

// initTables creates the necessary database tables
func (s *SQLiteStore) initTables() error {
	queries := []string{
		// Clients table
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			encrypted_secret TEXT,
			attestation_config TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Access tokens table
		`CREATE TABLE IF NOT EXISTS access_tokens (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Refresh tokens table
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Authorization codes table
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// PKCE table
		`CREATE TABLE IF NOT EXISTS pkce (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Client assertion JWT table
		`CREATE TABLE IF NOT EXISTS client_assertion_jwt (
			jti TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL
		)`,

		// Device codes table
		`CREATE TABLE IF NOT EXISTS device_codes (
			signature TEXT PRIMARY KEY,
			user_code TEXT,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Trust anchors table
		`CREATE TABLE IF NOT EXISTS trust_anchors (
			name TEXT PRIMARY KEY,
			certificate_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Upstream token mappings table for proxy mode
		`CREATE TABLE IF NOT EXISTS upstream_token_mappings (
			proxy_token_signature TEXT PRIMARY KEY,
			upstream_access_token TEXT NOT NULL,
			upstream_refresh_token TEXT,
			upstream_token_type TEXT NOT NULL DEFAULT 'bearer',
			upstream_expires_in INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %q: %w", query, err)
		}
	}

	s.logger.Info("✅ SQLite tables initialized")
	return nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Client storage methods
func (s *SQLiteStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM clients WHERE id = ?", id).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidClient
	}
	if err != nil {
		return nil, err
	}

	var client fosite.DefaultClient
	if err := json.Unmarshal([]byte(data), &client); err != nil {
		return nil, err
	}

	return &client, nil
}

func (s *SQLiteStore) GetAllClients(ctx context.Context) ([]fosite.Client, error) {
	rows, err := s.db.Query("SELECT data FROM clients")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []fosite.Client
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}

		var client fosite.DefaultClient
		if err := json.Unmarshal([]byte(data), &client); err != nil {
			return nil, err
		}

		clients = append(clients, &client)
	}

	return clients, nil
}

func (s *SQLiteStore) CreateClient(ctx context.Context, client fosite.Client) error {
	data, err := json.Marshal(client)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO clients (id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		client.GetID(), string(data),
	)
	return err
}

func (s *SQLiteStore) UpdateClient(ctx context.Context, id string, client fosite.Client) error {
	return s.CreateClient(ctx, client)
}

func (s *SQLiteStore) DeleteClient(ctx context.Context, id string) error {
	_, err := s.db.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}

// User storage methods (for local mode)
func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*storage.MemoryUserRelation, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM users WHERE id = ?", id).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	var user storage.MemoryUserRelation
	if err := json.Unmarshal([]byte(data), &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *SQLiteStore) CreateUser(ctx context.Context, id string, user *storage.MemoryUserRelation) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO users (id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		id, string(data),
	)
	return err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, id string, user *storage.MemoryUserRelation) error {
	return s.CreateUser(ctx, id, user)
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// Token storage methods
func (s *SQLiteStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	data, err := MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO access_tokens (signature, data) VALUES (?, ?)",
		signature, string(data),
	)
	return err
}

func (s *SQLiteStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM access_tokens WHERE signature = ?", signature).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	return s.UnmarshalRequestWithClientID([]byte(data))
}

func (s *SQLiteStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.Exec("DELETE FROM access_tokens WHERE signature = ?", signature)
	return err
}

func (s *SQLiteStore) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error {
	data, err := MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO refresh_tokens (signature, data) VALUES (?, ?)",
		signature, string(data),
	)
	return err
}

func (s *SQLiteStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM refresh_tokens WHERE signature = ?", signature).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	return s.UnmarshalRequestWithClientID([]byte(data))
}

func (s *SQLiteStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.Exec("DELETE FROM refresh_tokens WHERE signature = ?", signature)
	return err
}

func (s *SQLiteStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// For basic implementation, we don't rotate refresh tokens
	// This could be implemented to update the refresh token signature for security
	return nil
}

func (s *SQLiteStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	// For basic implementation, we don't revoke access tokens by request ID
	// This could be implemented to revoke all access tokens for a specific request
	return nil
}

func (s *SQLiteStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	// For basic implementation, we don't revoke refresh tokens by request ID
	// This could be implemented to revoke all refresh tokens for a specific request
	return nil
}

func (s *SQLiteStore) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	data, err := MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	s.logger.Debugf("🔍 SQLiteStore.CreateAuthorizeCodeSession: storing JSON: %s", string(data))

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO authorization_codes (signature, data) VALUES (?, ?)",
		code, string(data),
	)
	return err
}

func (s *SQLiteStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM authorization_codes WHERE signature = ?", code).Scan(&data)
	if err == sql.ErrNoRows {
		// If not found, try extracting the signature part (after the last dot)
		parts := strings.Split(code, ".")
		if len(parts) > 1 {
			signature := parts[len(parts)-1]
			s.logger.Debugf("🔍 SQLiteStore.GetAuthorizeCodeSession: trying signature part: %s", signature)
			err = s.db.QueryRow("SELECT data FROM authorization_codes WHERE signature = ?", signature).Scan(&data)
		}
	}

	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	s.logger.Debugf("🔍 SQLiteStore.GetAuthorizeCodeSession: unmarshaling JSON: %s", data)
	request, err := s.UnmarshalRequestWithClientID([]byte(data))
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.GetAuthorizeCodeSession: unmarshal error: %v", err)
		return nil, err
	}

	s.logger.Debugf("✅ SQLiteStore.GetAuthorizeCodeSession: successfully unmarshaled request with client: %T, ID: %s", request.GetClient(), request.GetClient().GetID())
	return request, nil
}

func (s *SQLiteStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	_, err := s.db.Exec("DELETE FROM authorization_codes WHERE signature = ?", code)
	return err
}

// PKCE methods
func (s *SQLiteStore) CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error {
	data, err := MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO pkce (signature, data) VALUES (?, ?)",
		code, string(data),
	)
	return err
}

func (s *SQLiteStore) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM pkce WHERE signature = ?", code).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	return s.UnmarshalRequestWithClientID([]byte(data))
}

func (s *SQLiteStore) DeletePKCERequestSession(ctx context.Context, code string) error {
	_, err := s.db.Exec("DELETE FROM pkce WHERE signature = ?", code)
	return err
}

// Client Assertion JWT methods
func (s *SQLiteStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var expiresAt time.Time
	err := s.db.QueryRow("SELECT expires_at FROM client_assertion_jwt WHERE jti = ?", jti).Scan(&expiresAt)
	if err == sql.ErrNoRows {
		return fosite.ErrInvalidRequest
	}
	if err != nil {
		return err
	}

	if time.Now().After(expiresAt) {
		return fosite.ErrInvalidRequest
	}

	return nil
}

func (s *SQLiteStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO client_assertion_jwt (jti, expires_at) VALUES (?, ?)",
		jti, exp,
	)
	return err
}

// Device authorization methods
func (s *SQLiteStore) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error) {
	s.logger.Debugf("🔍 SQLiteStore.GetDeviceCodeSession: looking for device code: %s", deviceCode)

	// Try the full device code first
	var data string
	err := s.db.QueryRow("SELECT data FROM device_codes WHERE signature = ?", deviceCode).Scan(&data)
	if err == sql.ErrNoRows {
		// If not found, try extracting the signature part (after the last dot)
		parts := strings.Split(deviceCode, ".")
		if len(parts) > 1 {
			signature := parts[len(parts)-1]
			s.logger.Debugf("🔍 SQLiteStore.GetDeviceCodeSession: trying signature part: %s", signature)
			err = s.db.QueryRow("SELECT data FROM device_codes WHERE signature = ?", signature).Scan(&data)
		}
	}

	if err == sql.ErrNoRows {
		s.logger.Errorf("❌ SQLiteStore.GetDeviceCodeSession: device code not found: %s", deviceCode)
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.GetDeviceCodeSession: database error: %v", err)
		return nil, err
	}

	s.logger.Debugf("✅ SQLiteStore.GetDeviceCodeSession: found device code data")
	return s.UnmarshalDeviceRequestWithClientID([]byte(data))
}

func (s *SQLiteStore) CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	s.logger.Debugf("🔍 SQLiteStore.CreateDeviceCodeSession: storing device code: %s", deviceCode)

	// Convert to DeviceRequester if needed
	var deviceReq fosite.DeviceRequester
	if dr, ok := request.(fosite.DeviceRequester); ok {
		deviceReq = dr
	} else {
		return fmt.Errorf("request is not a DeviceRequester")
	}

	data, err := MarshalDeviceRequestWithClientID(deviceReq)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO device_codes (signature, data) VALUES (?, ?)",
		deviceCode, string(data),
	)
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.CreateDeviceCodeSession: failed to store: %v", err)
	} else {
		s.logger.Debugf("✅ SQLiteStore.CreateDeviceCodeSession: successfully stored device code: %s", deviceCode)
	}
	return err
}

func (s *SQLiteStore) UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	s.logger.Debugf("🔍 SQLiteStore.UpdateDeviceCodeSession: updating device code: %s", deviceCode)

	// Convert to DeviceRequester if needed
	var deviceReq fosite.DeviceRequester
	if dr, ok := request.(fosite.DeviceRequester); ok {
		deviceReq = dr
	} else {
		return fmt.Errorf("request is not a DeviceRequester")
	}

	data, err := MarshalDeviceRequestWithClientID(deviceReq)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"UPDATE device_codes SET data = ? WHERE signature = ?",
		string(data), deviceCode,
	)
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.UpdateDeviceCodeSession: failed to update: %v", err)
	} else {
		s.logger.Debugf("✅ SQLiteStore.UpdateDeviceCodeSession: successfully updated device code: %s", deviceCode)
	}
	return err
}

func (s *SQLiteStore) InvalidateDeviceCodeSession(ctx context.Context, signature string) error {
	_, err := s.db.Exec("DELETE FROM device_codes WHERE signature = ?", signature)
	return err
}

func (s *SQLiteStore) GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error) {
	rows, err := s.db.Query("SELECT signature, data FROM device_codes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pending := make(map[string]fosite.Requester)
	for rows.Next() {
		var signature string
		var data string
		if err := rows.Scan(&signature, &data); err != nil {
			return nil, err
		}

		deviceReq, err := s.UnmarshalDeviceRequestWithClientID([]byte(data))
		if err != nil {
			return nil, err
		}

		pending[signature] = deviceReq
	}

	return pending, nil
}

func (s *SQLiteStore) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (fosite.DeviceRequester, string, error) {
	var signature string
	var data string
	err := s.db.QueryRow("SELECT signature, data FROM device_codes WHERE user_code = ?", userCode).Scan(&signature, &data)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("device authorization not found for user code: %s", userCode)
	}
	if err != nil {
		return nil, "", err
	}

	deviceReq, err := s.UnmarshalDeviceRequestWithClientID([]byte(data))
	if err != nil {
		return nil, "", err
	}

	return deviceReq, signature, nil
}

func (s *SQLiteStore) CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error {
	s.logger.Debugf("🔍 SQLiteStore.CreateDeviceAuthSession: storing device code: %s, user code: %s", deviceCodeSignature, userCodeSignature)

	data, err := MarshalDeviceRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO device_codes (signature, user_code, data) VALUES (?, ?, ?)",
		deviceCodeSignature, userCodeSignature, string(data),
	)
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.CreateDeviceAuthSession: failed to store: %v", err)
	} else {
		s.logger.Debugf("✅ SQLiteStore.CreateDeviceAuthSession: successfully stored device code: %s", deviceCodeSignature)
	}
	return err
}

// Helper methods for statistics
func (s *SQLiteStore) GetClientCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetUserCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetAccessTokenCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM access_tokens").Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetRefreshTokenCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	return count, err
}

// Secure client data storage methods
func (s *SQLiteStore) StoreClientSecret(ctx context.Context, clientID string, encryptedSecret string) error {
	_, err := s.db.Exec(
		"UPDATE clients SET encrypted_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		encryptedSecret, clientID,
	)
	return err
}

func (s *SQLiteStore) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	var encryptedSecret string
	err := s.db.QueryRow("SELECT encrypted_secret FROM clients WHERE id = ?", clientID).Scan(&encryptedSecret)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("client secret not found")
	}
	if err != nil {
		return "", err
	}
	return encryptedSecret, nil
}

func (s *SQLiteStore) StoreAttestationConfig(ctx context.Context, clientID string, config *config.ClientAttestationConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"UPDATE clients SET attestation_config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		string(data), clientID,
	)
	return err
}

func (s *SQLiteStore) GetAttestationConfig(ctx context.Context, clientID string) (*config.ClientAttestationConfig, error) {
	var data string
	err := s.db.QueryRow("SELECT attestation_config FROM clients WHERE id = ?", clientID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("attestation config not found")
	}
	if err != nil {
		return nil, err
	}

	var config config.ClientAttestationConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Trust anchor storage methods
func (s *SQLiteStore) StoreTrustAnchor(ctx context.Context, name string, certificateData []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO trust_anchors (name, certificate_data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		name, string(certificateData),
	)
	return err
}

func (s *SQLiteStore) GetTrustAnchor(ctx context.Context, name string) ([]byte, error) {
	var data string
	err := s.db.QueryRow("SELECT certificate_data FROM trust_anchors WHERE name = ?", name).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("trust anchor not found")
	}
	if err != nil {
		return nil, err
	}
	return []byte(data), nil
}

func (s *SQLiteStore) ListTrustAnchors(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query("SELECT name FROM trust_anchors ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func (s *SQLiteStore) DeleteTrustAnchor(ctx context.Context, name string) error {
	result, err := s.db.Exec("DELETE FROM trust_anchors WHERE name = ?", name)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("trust anchor not found")
	}
	return nil
}

// Upstream token mapping methods for proxy mode
func (s *SQLiteStore) StoreUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string, upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO upstream_token_mappings 
		 (proxy_token_signature, upstream_access_token, upstream_refresh_token, upstream_token_type, upstream_expires_in, updated_at) 
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		proxyTokenSignature, upstreamAccessToken, upstreamRefreshToken, upstreamTokenType, upstreamExpiresIn,
	)
	return err
}

func (s *SQLiteStore) GetUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) (upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64, err error) {
	var accessToken, refreshToken, tokenType string
	var expiresIn sql.NullInt64

	err = s.db.QueryRow(
		"SELECT upstream_access_token, upstream_refresh_token, upstream_token_type, upstream_expires_in FROM upstream_token_mappings WHERE proxy_token_signature = ?",
		proxyTokenSignature,
	).Scan(&accessToken, &refreshToken, &tokenType, &expiresIn)

	if err == sql.ErrNoRows {
		return "", "", "", 0, fmt.Errorf("upstream token mapping not found")
	}
	if err != nil {
		return "", "", "", 0, err
	}

	expiresInValue := int64(0)
	if expiresIn.Valid {
		expiresInValue = expiresIn.Int64
	}

	return accessToken, refreshToken, tokenType, expiresInValue, nil
}

func (s *SQLiteStore) DeleteUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) error {
	result, err := s.db.Exec("DELETE FROM upstream_token_mappings WHERE proxy_token_signature = ?", proxyTokenSignature)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("upstream token mapping not found")
	}
	return nil
}
