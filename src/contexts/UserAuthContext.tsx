import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { auth, onAuthStateChanged, User as FirebaseUser, signInAnonymously, firebaseConnectionPromise, checkFirestoreConnection, createUserWithEmailAndPassword, signInWithEmailAndPassword, db, doc, getDoc, setDoc } from '../firebase';
import toast from 'react-hot-toast';

export interface User {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  role: 'user' | 'admin';
  createdAt?: string;
}

interface UserAuthContextType {
  user: User | null;
  isAuthReady: boolean;
  isOnline: boolean;
  dbStatus: 'connected' | 'disconnected' | 'checking';
  dbTip: string | null;
  registerLocal: (name: string, email: string, pass: string) => Promise<void>;
  loginLocal: (email: string, pass: string) => Promise<void>;
  logout: () => Promise<void>;
}

const UserAuthContext = createContext<UserAuthContextType | undefined>(undefined);

export const UserAuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [isOnline, setIsOnline] = useState(true); // Default to true to avoid assuming offline
  const [dbStatus, setDbStatus] = useState<'connected' | 'disconnected' | 'checking'>('checking');
  const [dbTip, setDbTip] = useState<string | null>(null);

  useEffect(() => {
    // Ping server health and Firestore
    const checkConnectivity = async () => {
      try {
        // Check Firestore connectivity (Primary source of truth for "Online")
        const firestoreConnected = await checkFirestoreConnection();
        setIsOnline(firestoreConnected);
        
        // The app is "Online" if Firestore is reachable.
        setDbStatus(firestoreConnected ? 'connected' : 'disconnected');
        
        if (!firestoreConnected) {
          setDbTip("Firestore backend is unreachable. Check your Firebase configuration or wait for provisioning to complete.");
        } else {
          setDbTip(null);
        }
        
        console.log(`✅ Connectivity check: Firestore is ${firestoreConnected ? 'connected' : 'disconnected'}`);
      } catch (err) {
        console.error('❌ Connectivity check failed:', err);
        const firestoreConnected = await firebaseConnectionPromise;
        setIsOnline(firestoreConnected);
        setDbStatus(firestoreConnected ? 'connected' : 'disconnected');
      }
    };

    // Initial check
    checkConnectivity();

    // Dynamic updates: Network status listeners
    const handleOnline = () => {
      console.log("🌐 Browser reported online status");
      checkConnectivity();
    };
    const handleOffline = () => {
      console.log("🌐 Browser reported offline status");
      setIsOnline(false);
      setDbStatus('disconnected');
      setDbTip("You are currently offline. Please check your internet connection.");
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Periodic re-check every 60 seconds
    const interval = setInterval(checkConnectivity, 60000);

    const checkAuth = () => {
      // Check Firebase Auth
      const unsubscribe = onAuthStateChanged(auth, async (firebaseUser: FirebaseUser | null) => {
        if (firebaseUser) {
          try {
            // Fetch user profile from Firestore
            const userDoc = await getDoc(doc(db, 'users', firebaseUser.uid));
            
            if (userDoc.exists()) {
              const userData = userDoc.data() as User;
              setUser({
                ...userData,
                uid: firebaseUser.uid,
                email: firebaseUser.email || userData.email,
                displayName: userData.displayName || firebaseUser.displayName || '',
                photoURL: userData.photoURL || firebaseUser.photoURL || undefined,
                role: userData.role || 'user',
              });
            } else {
              console.warn("⚠️ User authenticated but no profile found in Firestore. Signing out.");
              await auth.signOut();
              setUser(null);
              toast.error("User profile not found. Please register.");
            }
          } catch (error) {
            console.error("❌ Error fetching user profile:", error);
            // If we're offline, we might not be able to fetch the profile.
            // But we should still set a basic user object if possible, or handle offline state.
            setUser({
              uid: firebaseUser.uid,
              email: firebaseUser.email || '',
              displayName: firebaseUser.displayName || '',
              photoURL: firebaseUser.photoURL || undefined,
              role: 'user',
            });
          }
        } else {
          setUser(null);
        }
        setIsAuthReady(true);
      });

      return unsubscribe;
    };

    const unsubscribe = checkAuth();
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      clearInterval(interval);
      unsubscribe && unsubscribe();
    };
  }, []);

  const registerLocal = async (name: string, email: string, pass: string) => {
    try {
      // 1. Create user in Firebase Auth
      const cred = await createUserWithEmailAndPassword(auth, email, pass);
      const uid = cred.user.uid;

      // 2. Create user profile in Firestore
      const userProfile = {
        uid,
        email,
        displayName: name,
        role: 'user' as const,
        createdAt: new Date().toISOString()
      };

      await setDoc(doc(db, 'users', uid), userProfile);
      
      setUser(userProfile);
      toast.success("Registration successful!");
      return { success: true };
    } catch (error: any) {
      console.error("❌ Registration error:", error);
      toast.error(error.message || "Registration failed");
      throw error;
    }
  };

  const loginLocal = async (email: string, pass: string) => {
    try {
      // 1. Sign in with Firebase Auth
      const cred = await signInWithEmailAndPassword(auth, email, pass);
      const uid = cred.user.uid;

      // 2. Fetch user profile from Firestore
      const userDoc = await getDoc(doc(db, 'users', uid));
      
      if (!userDoc.exists()) {
        // If user exists in Auth but not in Firestore, we should sign them out
        await auth.signOut();
        throw new Error("User profile not found in database. Please register first.");
      }

      const userData = userDoc.data() as User;
      setUser(userData);
      toast.success("Login successful!");
      return { success: true };
    } catch (error: any) {
      console.error("❌ Login error:", error);
      toast.error(error.message || "Login failed");
      throw error;
    }
  };

  const logout = async () => {
    await auth.signOut();
    setUser(null);
    toast.success("Logged out");
  };

  return (
    <UserAuthContext.Provider value={{ user, isAuthReady, isOnline, dbStatus, dbTip, registerLocal, loginLocal, logout }}>
      {children}
    </UserAuthContext.Provider>
  );
};

export const useUserAuth = () => {
  const context = useContext(UserAuthContext);
  if (context === undefined) {
    throw new Error('useUserAuth must be used within a UserAuthProvider');
  }
  return context;
};
