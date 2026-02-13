-- Add up migration script here
-- 1. Create a custom Type for Roles
CREATE TYPE user_role AS ENUM ('user', 'moderator', 'admin');
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Create the Users Table
CREATE TABLE users (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255),
    role user_role DEFAULT 'user' NOT NULL,
    phone_number VARCHAR(15) UNIQUE,

    -- In Mongo you had nested objects. In Postgres, we use JSONB for flexibility
    profile_picture JSONB DEFAULT '{"url": "http://localhost:8081/uploads/default/avatar.jpg"}'::jsonb,
    contact_preferences JSONB DEFAULT '{"phone": true, "email": true, "whatsapp": true}'::jsonb,
    preferences JSONB,

    trust_score INT DEFAULT 10 CHECK (trust_score >= 0 AND trust_score <= 100),
    is_banned BOOLEAN DEFAULT false,

    -- Verification fields
    email_verified BOOLEAN DEFAULT false,
    phone_verified BOOLEAN DEFAULT false,

    -- Location (We'll store this as JSONB for now to keep it simple)
    location JSONB DEFAULT '{"country": "Nigeria"}'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone_number ON users(phone_number);
CREATE INDEX idx_users_role ON users(role);
