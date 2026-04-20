DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_oauth_providers_updated_at ON oauth_providers;

DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS oauth_providers;

DROP TABLE IF EXISTS users;

DROP FUNCTION IF EXISTS update_updated_at_column;

DROP TYPE IF EXISTS user_role;

DROP EXTENSION IF EXISTS "uuid-ossp";
