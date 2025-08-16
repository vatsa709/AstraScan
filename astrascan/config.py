# astrascan_project/astrascan/config.py

# Global constants for the scanner
COMMON_SUFFIXES = [
    "v1", "v2", "api", "dev", "internal", "test", "graphql", "debug", "admin",
    "config", "users", "data", ".env", ".git/HEAD", "swagger.json",
    "openapi.json", "docs", "health", "status", "info", "metrics", "prometheus",
    "actuator", "app", "version", "schema", "api/status", "admin/dashboard",
    "login", "auth", "register", "profile", "settings", "notifications",
    "products", "orders", "items", "search", "upload", "download", "files",
    "images", "reports", "export", "import", "billing", "payments", "transactions"
]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# GraphQL Introspection Query (Standard)
GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""
