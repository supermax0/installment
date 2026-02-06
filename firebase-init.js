/**
 * Firebase Initialization and Database Manager
 * يدير عمليات قاعدة البيانات مع Firestore و Realtime Database
 */

// انتظر تحميل Firebase
let db = null;
let realtimeDb = null;
let firebaseReady = false;

// تهيئة Firebase
function initFirebase() {
  if (typeof firebase === 'undefined') {
    console.error('Firebase SDK not loaded');
    return false;
  }

  try {
    // Firebase configuration
    const firebaseConfig = {
      apiKey: "AIzaSyB0RdjBog7T1QIMVXKNpjatrZSdVHkFI-Q",
      authDomain: "installments-e4139.firebaseapp.com",
      databaseURL: "https://installments-e4139-default-rtdb.firebaseio.com",
      projectId: "installments-e4139",
      storageBucket: "installments-e4139.firebasestorage.app",
      messagingSenderId: "640639457619",
      appId: "1:640639457619:web:c99818d5e0134c6817e9a6",
      measurementId: "G-5R1J8BQS0X"
    };

    // Initialize Firebase (avoid double init)
    if (firebase.apps && firebase.apps.length > 0) {
      // already initialized
    } else {
      firebase.initializeApp(firebaseConfig);
    }
    
    // Initialize Firestore
    db = firebase.firestore();
    
    // Initialize Realtime Database
    realtimeDb = firebase.database();
    
    firebaseReady = true;
    console.log('Firebase initialized successfully');
    
    return true;
  } catch (error) {
    console.error('Error initializing Firebase:', error);
    return false;
  }
}

// ========== Firestore Functions ==========

/**
 * الحصول على جميع العملاء من Firestore
 */
async function getCustomersFirestore() {
  if (!firebaseReady) return [];
  try {
    const snapshot = await db.collection("customers").get();
    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  } catch (error) {
    console.error("Error getting customers:", error);
    return [];
  }
}

/**
 * حفظ عميل في Firestore
 */
async function saveCustomerFirestore(customer) {
  if (!firebaseReady) return false;
  try {
    await db.collection("customers").doc(customer.id).set(customer);
    return true;
  } catch (error) {
    console.error("Error saving customer:", error);
    return false;
  }
}

/**
 * حذف عميل من Firestore
 */
async function deleteCustomerFirestore(customerId) {
  if (!firebaseReady) return false;
  try {
    await db.collection("customers").doc(customerId).delete();
    return true;
  } catch (error) {
    console.error("Error deleting customer:", error);
    return false;
  }
}

/**
 * الحصول على جميع المبيعات من Firestore
 */
async function getSalesFirestore() {
  if (!firebaseReady) return [];
  try {
    const snapshot = await db.collection("sales").orderBy("date", "desc").get();
    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  } catch (error) {
    console.error("Error getting sales:", error);
    return [];
  }
}

/**
 * حفظ بيع في Firestore
 */
async function saveSaleFirestore(sale) {
  if (!firebaseReady) return false;
  try {
    await db.collection("sales").doc(sale.id).set(sale);
    return true;
  } catch (error) {
    console.error("Error saving sale:", error);
    return false;
  }
}

/**
 * تحديث بيع في Firestore
 */
async function updateSaleFirestore(saleId, updates) {
  if (!firebaseReady) return false;
  try {
    await db.collection("sales").doc(saleId).update(updates);
    return true;
  } catch (error) {
    console.error("Error updating sale:", error);
    return false;
  }
}

/**
 * حذف بيع من Firestore
 */
async function deleteSaleFirestore(saleId) {
  if (!firebaseReady) return false;
  try {
    await db.collection("sales").doc(saleId).delete();
    return true;
  } catch (error) {
    console.error("Error deleting sale:", error);
    return false;
  }
}

/**
 * الحصول على جميع الحركات من Firestore
 */
async function getActivityFirestore() {
  if (!firebaseReady) return [];
  try {
    const snapshot = await db.collection("activity").orderBy("date", "desc").get();
    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  } catch (error) {
    console.error("Error getting activity:", error);
    return [];
  }
}

/**
 * إضافة حركة في Firestore
 */
async function addActivityFirestore(activity) {
  if (!firebaseReady) return false;
  try {
    await db.collection("activity").add({ ...activity, id: Date.now().toString() });
    return true;
  } catch (error) {
    console.error("Error adding activity:", error);
    return false;
  }
}

/**
 * الحصول على الإعدادات من Firestore
 */
async function getSettingsFirestore() {
  if (!firebaseReady) return null;
  try {
    const doc = await db.collection("settings").doc("app").get();
    if (doc.exists) {
      return doc.data();
    }
    return null;
  } catch (error) {
    console.error("Error getting settings:", error);
    return null;
  }
}

/**
 * حفظ الإعدادات في Firestore
 */
async function saveSettingsFirestore(settings) {
  if (!firebaseReady) return false;
  try {
    await db.collection("settings").doc("app").set(settings);
    return true;
  } catch (error) {
    console.error("Error saving settings:", error);
    return false;
  }
}

// ========== App Data (Single Document) ==========
/**
 * قراءة كل بيانات التطبيق كوثيقة واحدة (Firestore)
 * تسهل المزامنة بين المتصفحات بدون تعديل كبير على app.js
 */
async function getAppDataFirestore() {
  if (!firebaseReady) return null;
  try {
    const docSnap = await db.collection("appData").doc("app").get();
    if (!docSnap.exists) return null;
    return docSnap.data();
  } catch (error) {
    console.error("Error getting app data:", error);
    return null;
  }
}

/**
 * حفظ كل بيانات التطبيق كوثيقة واحدة (Firestore)
 */
async function setAppDataFirestore(data) {
  if (!firebaseReady) return false;
  try {
    await db.collection("appData").doc("app").set(data);
    return true;
  } catch (error) {
    console.error("Error saving app data:", error);
    return false;
  }
}

// ========== Auth Users (Single Document) ==========
/**
 * قراءة مستخدمي تسجيل الدخول (Firestore)
 * نخزنهم كوثيقة واحدة لسهولة المزامنة بين الأجهزة
 * ملاحظة: لا نخزن كلمات مرور صريحة، فقط hash + salt
 */
async function getAuthUsersFirestore() {
  if (!firebaseReady) return null;
  try {
    const docSnap = await db.collection("auth").doc("users").get();
    if (!docSnap.exists) return null;
    return docSnap.data();
  } catch (error) {
    console.error("Error getting auth users:", error);
    return null;
  }
}

/**
 * حفظ مستخدمي تسجيل الدخول (Firestore)
 */
async function setAuthUsersFirestore(data) {
  if (!firebaseReady) return false;
  try {
    await db.collection("auth").doc("users").set(data);
    return true;
  } catch (error) {
    console.error("Error saving auth users:", error);
    return false;
  }
}

// ========== Realtime Database Functions ==========

/**
 * الحصول على جميع العملاء من Realtime Database
 */
async function getCustomersRealtime() {
  if (!firebaseReady) return [];
  try {
    const snapshot = await realtimeDb.ref("customers").once("value");
    if (snapshot.exists()) {
      return Object.keys(snapshot.val()).map(key => ({
        id: key,
        ...snapshot.val()[key]
      }));
    }
    return [];
  } catch (error) {
    console.error("Error getting customers:", error);
    return [];
  }
}

/**
 * حفظ عميل في Realtime Database
 */
async function saveCustomerRealtime(customer) {
  if (!firebaseReady) return false;
  try {
    await realtimeDb.ref(`customers/${customer.id}`).set(customer);
    return true;
  } catch (error) {
    console.error("Error saving customer:", error);
    return false;
  }
}

/**
 * حذف عميل من Realtime Database
 */
async function deleteCustomerRealtime(customerId) {
  if (!firebaseReady) return false;
  try {
    await realtimeDb.ref(`customers/${customerId}`).remove();
    return true;
  } catch (error) {
    console.error("Error deleting customer:", error);
    return false;
  }
}

/**
 * الحصول على جميع المبيعات من Realtime Database
 */
async function getSalesRealtime() {
  if (!firebaseReady) return [];
  try {
    const snapshot = await realtimeDb.ref("sales").once("value");
    if (snapshot.exists()) {
      return Object.keys(snapshot.val()).map(key => ({
        id: key,
        ...snapshot.val()[key]
      }));
    }
    return [];
  } catch (error) {
    console.error("Error getting sales:", error);
    return [];
  }
}

/**
 * حفظ بيع في Realtime Database
 */
async function saveSaleRealtime(sale) {
  if (!firebaseReady) return false;
  try {
    await realtimeDb.ref(`sales/${sale.id}`).set(sale);
    return true;
  } catch (error) {
    console.error("Error saving sale:", error);
    return false;
  }
}

/**
 * تحديث بيع في Realtime Database
 */
async function updateSaleRealtime(saleId, updates) {
  if (!firebaseReady) return false;
  try {
    await realtimeDb.ref(`sales/${saleId}`).update(updates);
    return true;
  } catch (error) {
    console.error("Error updating sale:", error);
    return false;
  }
}

/**
 * حذف بيع من Realtime Database
 */
async function deleteSaleRealtime(saleId) {
  if (!firebaseReady) return false;
  try {
    await realtimeDb.ref(`sales/${saleId}`).remove();
    return true;
  } catch (error) {
    console.error("Error deleting sale:", error);
    return false;
  }
}

/**
 * الحصول على جميع الحركات من Realtime Database
 */
async function getActivityRealtime() {
  if (!firebaseReady) return [];
  try {
    const snapshot = await realtimeDb.ref("activity").once("value");
    if (snapshot.exists()) {
      return Object.keys(snapshot.val()).map(key => ({
        id: key,
        ...snapshot.val()[key]
      }));
    }
    return [];
  } catch (error) {
    console.error("Error getting activity:", error);
    return [];
  }
}

/**
 * إضافة حركة في Realtime Database
 */
async function addActivityRealtime(activity) {
  if (!firebaseReady) return false;
  try {
    await realtimeDb.ref("activity").push({ ...activity, id: Date.now().toString() });
    return true;
  } catch (error) {
    console.error("Error adding activity:", error);
    return false;
  }
}

/**
 * الاستماع للتغييرات في الوقت الفعلي (Realtime Database)
 */
function subscribeToCustomersRealtime(callback) {
  if (!firebaseReady) return null;
  return realtimeDb.ref("customers").on("value", (snapshot) => {
    if (snapshot.exists()) {
      const customers = Object.keys(snapshot.val()).map(key => ({
        id: key,
        ...snapshot.val()[key]
      }));
      callback(customers);
    } else {
      callback([]);
    }
  });
}

function subscribeToSalesRealtime(callback) {
  if (!firebaseReady) return null;
  return realtimeDb.ref("sales").on("value", (snapshot) => {
    if (snapshot.exists()) {
      const sales = Object.keys(snapshot.val()).map(key => ({
        id: key,
        ...snapshot.val()[key]
      }));
      callback(sales);
    } else {
      callback([]);
    }
  });
}

// ========== Firestore Real-time Listeners ==========

/**
 * الاستماع للتغييرات في الوقت الفعلي (Firestore)
 */
function subscribeToCustomersFirestore(callback) {
  if (!firebaseReady) return null;
  return db.collection("customers").onSnapshot((snapshot) => {
    const customers = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    callback(customers);
  });
}

function subscribeToSalesFirestore(callback) {
  if (!firebaseReady) return null;
  return db.collection("sales").orderBy("date", "desc").onSnapshot((snapshot) => {
    const sales = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    callback(sales);
  });
}

// Export functions to window object
window.firebaseDB = {
  init: initFirebase,
  ready: () => firebaseReady,
  
  // Firestore
  getCustomersFirestore,
  saveCustomerFirestore,
  deleteCustomerFirestore,
  getSalesFirestore,
  saveSaleFirestore,
  updateSaleFirestore,
  deleteSaleFirestore,
  getActivityFirestore,
  addActivityFirestore,
  getSettingsFirestore,
  saveSettingsFirestore,
  subscribeToCustomersFirestore,
  subscribeToSalesFirestore,
  getAppDataFirestore,
  setAppDataFirestore,
  getAuthUsersFirestore,
  setAuthUsersFirestore,
  
  // Realtime Database
  getCustomersRealtime,
  saveCustomerRealtime,
  deleteCustomerRealtime,
  getSalesRealtime,
  saveSaleRealtime,
  updateSaleRealtime,
  deleteSaleRealtime,
  getActivityRealtime,
  addActivityRealtime,
  subscribeToCustomersRealtime,
  subscribeToSalesRealtime
};
