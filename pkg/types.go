package keycloak

type BaseKeycloakEvent struct {
	ID      string `json:"id"`
	Error   string `json:"error"`
	RealmID string `json:"realmId"`
	Time    int64  `json:"time"`
}

type KeycloakUserEvent struct {
	BaseKeycloakEvent
	Type      string      `json:"type"`
	ClientID  string      `json:"clientId"`
	UserID    string      `json:"userId"`
	SessionID string      `json:"sessionId"`
	IPAddress string      `json:"ipAddress"`
	Details   interface{} `json:"details"`
}

type AuthDetails struct {
	RealmID   string `json:"realmId"`
	ClientID  string `json:"clientId"`
	UserID    string `json:"userId"`
	IPAddress string `json:"ipAddress"`
}

type KeycloakAdminEvent struct {
	BaseKeycloakEvent
	AuthDetails       AuthDetails `json:"authDetails"`
	ResourceType      string      `json:"resourceType"` // This is the resource the AdminEvent was triggered for.
	OperationType     string      `json:"operationType"`
	ResourcePath      string      `json:"resourcePath"`
	RepresentationRaw string      `json:"representation"`
	Representation    interface{}
}
