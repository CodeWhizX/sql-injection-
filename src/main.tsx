import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App.tsx';
import './index.css';
import { AuthProvider } from './contexts/AuthContext';
import { UserAuthProvider } from './contexts/UserAuthContext';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <UserAuthProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </UserAuthProvider>
    </AuthProvider>
  </StrictMode>,
);
