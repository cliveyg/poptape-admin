package testutils

// DefaultCreateCredsPayload returns a flat map with all required fields for a CreateCreds request.
// Modify the returned map in your test as needed for specific scenarios.
func DefaultCreateCredsPayload() map[string]interface{} {
	return map[string]interface{}{
		"db_name":     "poptape_items",
		"type":        "mongo",
		"url":         "/items",
		"db_username": "poptape_items",
		"db_password": "cGFzc3dvcmQ=",
		"db_port":     "27017",
		"host":        "poptape-items-mongodb-1",
		"role_name":   "items",
		"ms_name":     "items",
	}
}
