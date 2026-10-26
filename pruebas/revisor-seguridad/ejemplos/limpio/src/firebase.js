import { initializeApp } from 'firebase/app';

// Configuración web de Firebase: es pública; la seguridad está en firestore.rules.
const firebaseConfig = {
  apiKey: '@@FIREBASE_KEY@@',
  authDomain: 'tienda-segura.firebaseapp.com',
  projectId: 'tienda-segura',
};

export const appFirebase = initializeApp(firebaseConfig);
