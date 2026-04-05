import React, { createContext, useContext, useState, ReactNode } from 'react';

export interface AuthConfig {
  method: 'Form-Based' | 'JSON/API' | 'Header-Based' | 'API-Token' | 'Session-Cookie' | 'OAuth2-Bearer';
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  credentials: {
    user: string;
    pass: string;
  };
  token: string;
  tokenHeader: string;
  isAuthenticated: boolean;
  sessionCookies: string;
  authenticatedBaseline: string;
  verifySsl: boolean;
  heartbeatInterval: number;
  autoReauth: boolean;
  reauthThreshold: number; // Percentage of failed requests before re-auth
}

interface AuthContextType {
  authConfig: AuthConfig;
  setAuthConfig: React.Dispatch<React.SetStateAction<AuthConfig>>;
  authConfigured: boolean;
  setAuthConfigured: React.Dispatch<React.SetStateAction<boolean>>;
}

const defaultAuthConfig: AuthConfig = {
  method: 'Form-Based',
  loginUrl: '',
  usernameField: 'username',
  passwordField: 'password',
  credentials: { user: 'admin', pass: 'password123' },
  token: '',
  tokenHeader: 'Authorization',
  isAuthenticated: false,
  sessionCookies: '',
  authenticatedBaseline: 'Sign Out',
  verifySsl: true,
  heartbeatInterval: 30,
  autoReauth: true,
  reauthThreshold: 15
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [authConfig, setAuthConfig] = useState<AuthConfig>(defaultAuthConfig);
  const [authConfigured, setAuthConfigured] = useState(false);

  return (
    <AuthContext.Provider value={{ authConfig, setAuthConfig, authConfigured, setAuthConfigured }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
