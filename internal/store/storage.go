package store

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"time"

	"oauth2-server/internal/store/types"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8693"
)

// Storage is an alias for the Storage interface defined in the types package
type Storage = types.Storage

// getRequestFields uses reflection to get fields from a fosite.Requester to avoid method calls that may do type assertions
func getRequestFields(request fosite.Requester) map[string]interface{} {
	fields := make(map[string]interface{})

	var collect func(reflect.Value)
	collect = func(v reflect.Value) {
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		if !v.IsValid() {
			return
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
			case "GrantedScope", "GrantedScopes":
				if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String {
					fields["granted_scopes"] = field.Interface()
				}
			case "RequestedScope", "RequestedScopes":
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
			case "Request":
				// Recurse into embedded Request to capture requested/granted scopes/audience
				collect(field)
			}
		}
	}

	collect(reflect.ValueOf(request))
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
