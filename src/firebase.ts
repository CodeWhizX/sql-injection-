import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, onAuthStateChanged, User, signInWithEmailAndPassword, createUserWithEmailAndPassword, updateProfile, signOut, signInAnonymously } from 'firebase/auth';
import { getFirestore, collection, doc, setDoc, getDoc, getDocs, query, where, onSnapshot, Timestamp, getDocFromServer, addDoc, updateDoc, deleteDoc } from 'firebase/firestore';

// Import the Firebase configuration
import firebaseConfig from '../firebase-applet-config.json';

console.log("🔥 Initializing Firebase with config:", {
  projectId: firebaseConfig.projectId,
  databaseId: firebaseConfig.firestoreDatabaseId,
  authDomain: firebaseConfig.authDomain
});

// Initialize Firebase SDK
const app = initializeApp(firebaseConfig);

// Initialize Firestore instance once with error handling
export const db = (() => {
  try {
    // Use named database if provided in config, otherwise falls back to (default)
    return getFirestore(app, firebaseConfig.firestoreDatabaseId || undefined);
  } catch (err) {
    console.error("❌ Failed to initialize Firestore:", err);
    // Fallback to default database instance
    return getFirestore(app);
  }
})();

export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

// Error handling for Firestore
export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId: string | undefined;
    email: string | null | undefined;
    emailVerified: boolean | undefined;
    isAnonymous: boolean | undefined;
    tenantId: string | null | undefined;
    providerInfo: {
      providerId: string;
      displayName: string | null;
      email: string | null;
      photoUrl: string | null;
    }[];
  }
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null) {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo: auth.currentUser?.providerData.map(provider => ({
        providerId: provider.providerId,
        displayName: provider.displayName,
        email: provider.email,
        photoUrl: provider.photoURL
      })) || []
    },
    operationType,
    path
  }
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// Function to test connection by writing a sample document
export const checkFirestoreConnection = async (): Promise<boolean> => {
  try {
    console.log("📡 Testing Firestore connection with write test...");
    const testDocRef = doc(db, 'test_connection', 'connectivity_check');
    
    // Perform a write test
    const writeTest = setDoc(testDocRef, {
      lastChecked: Timestamp.now(),
      status: 'online'
    }, { merge: true });

    const timeout = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Firestore connection timeout')), 10000)
    );

    await Promise.race([writeTest, timeout]);
    console.log("✅ Firestore connected successfully (Write test passed)");
    return true;
  } catch (error: any) {
    // If we get a permission-denied error, we ARE connected to the server, 
    // just not authorized to write to that specific document.
    if (error.code === 'permission-denied') {
      console.log("✅ Firestore connected successfully (Server reached, but write access restricted)");
      return true;
    }

    if (error.code === 'unavailable') {
      console.warn("⚠️ Firestore is currently unavailable. This is common during initial provisioning or if you are offline.");
    } else if (error.message?.includes('the client is offline') || error.code === 'failed-precondition') {
      console.error("❌ Firestore connection error: The client is offline or configuration is invalid.");
    } else {
      console.error("❌ Firestore connection test failed:", error.message || error);
    }
    return false;
  }
};

// Test connection by writing a sample document
export const firebaseConnectionPromise = checkFirestoreConnection();

export { 
  signInWithPopup, 
  onAuthStateChanged, 
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  signOut,
  signInAnonymously,
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  getDocs, 
  query, 
  where, 
  onSnapshot, 
  addDoc, 
  updateDoc, 
  deleteDoc,
  getDocFromServer,
  Timestamp 
};
export type { User };
