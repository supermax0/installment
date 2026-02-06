/**
 * نظام تتبع الديون والأقساط
 * البيانات تُخزن في localStorage
 */

const STORAGE_KEYS = {
  customers: 'installments_customers',
  sales: 'installments_sales',
  activity: 'installments_activity',
  settings: 'installments_settings',
  externalDebts: 'installments_external_debts',
  externalDebtTypes: 'installments_external_debt_types'
};

// ========== Cloud Sync (Firebase) ==========
const CLOUD_SYNC_KEYS = {
  localUpdatedAt: 'installments_cloud_updatedAt'
};

let cloudSyncStarted = false;
let cloudSyncApplying = false;
let cloudPushTimer = null;
let cloudPullTimer = null;

function getLocalUpdatedAt() {
  const n = Number(localStorage.getItem(CLOUD_SYNC_KEYS.localUpdatedAt) || 0);
  return Number.isFinite(n) ? n : 0;
}

function setLocalUpdatedAt(ts) {
  const n = Number(ts || 0);
  localStorage.setItem(CLOUD_SYNC_KEYS.localUpdatedAt, String(Number.isFinite(n) ? n : 0));
}

function touchLocalUpdatedAt() {
  setLocalUpdatedAt(Date.now());
}

function canUseCloudSync() {
  return (
    typeof window !== 'undefined' &&
    typeof window.firebaseDB !== 'undefined' &&
    typeof window.firebaseDB.ready === 'function' &&
    window.firebaseDB.ready() &&
    typeof window.firebaseDB.getAppDataFirestore === 'function' &&
    typeof window.firebaseDB.setAppDataFirestore === 'function'
  );
}

function collectLocalAppData() {
  return {
    customers: getCustomers(),
    sales: getSales(),
    activity: getActivity(),
    settings: getSettings(),
    externalDebts: getExternalDebts(),
    externalDebtTypes: getExternalDebtTypes()
  };
}

function rerenderAfterCloudSync() {
  try {
    fillSaleCustomerSelect();
    renderDashboard();
    renderCustomers();
    renderSalesList('', 'all');
    renderExternalDebts();
    renderActivity();
    renderLateList();
    updateLateBadge();
    renderUpcomingInstallments();
    renderSettings();
    updateDataInfo();
    updateBrowserInfo();
  } catch (e) {
    console.warn('Cloud sync rerender failed', e);
  }
}

async function pushToCloudNow(reason = '') {
  if (!canUseCloudSync()) return false;
  if (cloudSyncApplying) return false;
  try {
    const payload = collectLocalAppData();
    const updatedAt = Date.now();
    const ok = await window.firebaseDB.setAppDataFirestore({
      ...payload,
      updatedAt,
      reason
    });
    if (ok) {
      setLocalUpdatedAt(updatedAt);
    }
    return ok;
  } catch (e) {
    console.warn('Cloud push failed', e);
    return false;
  }
}

function scheduleCloudPush(reason = '') {
  if (!canUseCloudSync()) return;
  if (cloudSyncApplying) return;
  clearTimeout(cloudPushTimer);
  cloudPushTimer = setTimeout(() => {
    pushToCloudNow(reason);
  }, 800);
}

async function pullFromCloudIfNewer() {
  if (!canUseCloudSync()) return;
  if (cloudSyncApplying) return;
  try {
    const remote = await window.firebaseDB.getAppDataFirestore();
    if (!remote || typeof remote !== 'object') return;

    const remoteAt = Number(remote.updatedAt || 0);
    const localAt = getLocalUpdatedAt();

    const remoteHasAny =
      (Array.isArray(remote.customers) && remote.customers.length > 0) ||
      (Array.isArray(remote.sales) && remote.sales.length > 0) ||
      (Array.isArray(remote.activity) && remote.activity.length > 0) ||
      (Array.isArray(remote.externalDebts) && remote.externalDebts.length > 0) ||
      (remote.settings && typeof remote.settings === 'object');

    // إذا ما عندنا timestamp محلي والريموت عنده بيانات، نسحب
    const shouldPull =
      (remoteAt > 0 && remoteAt > localAt) ||
      (localAt === 0 && remoteHasAny);

    if (!shouldPull) return;

    cloudSyncApplying = true;
    if (Array.isArray(remote.customers)) setCustomers(remote.customers);
    if (Array.isArray(remote.sales)) setSales(remote.sales);
    if (Array.isArray(remote.activity)) setActivity(remote.activity);
    if (Array.isArray(remote.externalDebts)) setExternalDebts(remote.externalDebts);
    if (Array.isArray(remote.externalDebtTypes)) setExternalDebtTypes(remote.externalDebtTypes);
    if (remote.settings && typeof remote.settings === 'object') setSettings(remote.settings);
    setLocalUpdatedAt(remoteAt || Date.now());
    cloudSyncApplying = false;

    rerenderAfterCloudSync();
    toast('تمت المزامنة بين المتصفحات', 'success');
  } catch (e) {
    cloudSyncApplying = false;
    console.warn('Cloud pull failed', e);
  }
}

async function initialCloudSync() {
  if (!canUseCloudSync()) return;
  try {
    const remote = await window.firebaseDB.getAppDataFirestore();
    const local = collectLocalAppData();
    const localAt = getLocalUpdatedAt();
    const remoteAt = Number(remote?.updatedAt || 0);

    const localHasAny =
      (local.customers && local.customers.length > 0) ||
      (local.sales && local.sales.length > 0) ||
      (local.activity && local.activity.length > 0) ||
      (local.externalDebts && local.externalDebts.length > 0);

    const remoteHasAny =
      (remote && Array.isArray(remote.customers) && remote.customers.length > 0) ||
      (remote && Array.isArray(remote.sales) && remote.sales.length > 0) ||
      (remote && Array.isArray(remote.activity) && remote.activity.length > 0) ||
      (remote && Array.isArray(remote.externalDebts) && remote.externalDebts.length > 0);

    if (remote && (remoteAt > localAt || (localAt === 0 && remoteHasAny && !localHasAny))) {
      // اسحب من السحابة
      await pullFromCloudIfNewer();
      return;
    }

    if (localHasAny && (!remote || remoteAt < localAt || !remoteHasAny)) {
      // ادفع المحلي للسحابة
      await pushToCloudNow('initial');
      toast('تم ربط المزامنة السحابية', 'success');
    }
  } catch (e) {
    console.warn('Initial cloud sync failed', e);
  }
}

function startCloudSync() {
  if (cloudSyncStarted) return;
  cloudSyncStarted = true;

  // انتظر Firebase يصير جاهز
  let tries = 0;
  const wait = setInterval(() => {
    tries++;
    if (canUseCloudSync()) {
      clearInterval(wait);
      initialCloudSync();
      clearInterval(cloudPullTimer);
      cloudPullTimer = setInterval(() => {
        pullFromCloudIfNewer();
      }, 12000);
    }
    if (tries >= 20) {
      clearInterval(wait);
    }
  }, 500);
}

// ========== الفلاتر المتقدمة ==========
let advancedFilters = {
  dateFrom: null,
  dateTo: null,
  amountMin: null,
  amountMax: null
};

// ========== صلاحية إشعارات المتصفح ==========
// لازم تكون معرفة قبل renderSettings() حتى لا يصير ReferenceError
let notificationPermission = 'denied';
try {
  notificationPermission = (typeof window !== 'undefined' && 'Notification' in window)
    ? Notification.permission
    : 'denied';
} catch (_) {
  notificationPermission = 'denied';
}

// تهيئة التطبيق
function initApp() {
  renderDashboard();
  updateLateBadge();
  renderUpcomingInstallments();
  fillSaleCustomerSelect();
  renderCustomers();
  renderSalesList();
  renderExternalDebts();
  renderActivity();
  renderLateList();
  renderSettings();
  updateDataInfo();
  updateBrowserInfo();
  
  // تهيئة Firebase إذا كان متاحاً
  if (typeof window.firebaseDB !== 'undefined') {
    window.firebaseDB.init();
  }
  
  // تهيئة event listeners بعد التأكد من وجود العناصر
  initEventListeners();

  // تفعيل المزامنة السحابية بين المتصفحات (إن توفر Firebase)
  startCloudSync();
}

function initEventListeners() {
  // التأكد من وجود العناصر قبل إضافة event listeners
  const safeAddListener = (id, event, handler) => {
    const element = document.getElementById(id);
    if (element) {
      element.addEventListener(event, handler);
    } else {
      console.warn(`Element with id "${id}" not found`);
    }
  };
  
  const safeQueryAll = (selector, event, handler) => {
    const elements = document.querySelectorAll(selector);
    if (elements.length > 0) {
      elements.forEach(el => el.addEventListener(event, handler));
    }
  };
  
  // Menu and Sidebar
  safeAddListener('menuBtn', 'click', () => {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.toggle('open');
  });
  
  safeAddListener('sidebarOverlay', 'click', closeSidebar);
  
  // Navigation Links
  safeQueryAll('.nav-link', 'click', (e) => {
    e.preventDefault();
    const link = e.currentTarget;
    if (link.dataset.page) {
      showPage(link.dataset.page);
      closeSidebar();
    }
  });
  
  // Customer Form
  safeAddListener('openCustomerForm', 'click', () => openCustomerModal());
  safeAddListener('closeCustomerModal', 'click', () => {
    const modal = document.getElementById('customerModal');
    if (modal) modal.classList.remove('open');
  });
  safeAddListener('customerForm', 'submit', saveCustomer);
  
  // Customer Filters
  safeQueryAll('[data-customer-filter]', 'click', (e) => {
    document.querySelectorAll('[data-customer-filter]').forEach(b => b.classList.remove('active'));
    e.currentTarget.classList.add('active');
    const categoryFilter = e.currentTarget.dataset.customerFilter;
    const searchValue = document.getElementById('customerSearch')?.value || '';
    renderCustomers(searchValue, categoryFilter);
  });
  
  const customerSearch = document.getElementById('customerSearch');
  if (customerSearch) {
    customerSearch.addEventListener('input', (e) => {
      const val = e.target.value;
      const clearBtn = document.getElementById('clearCustomerSearch');
      if (clearBtn) clearBtn.style.display = val ? 'block' : 'none';
      const categoryFilter = document.querySelector('[data-customer-filter].active')?.dataset.customerFilter || 'all';
      renderCustomers(val, categoryFilter);
    });
  }
  
  safeAddListener('clearCustomerSearch', 'click', () => {
    const search = document.getElementById('customerSearch');
    const clearBtn = document.getElementById('clearCustomerSearch');
    if (search) search.value = '';
    if (clearBtn) clearBtn.style.display = 'none';
    const categoryFilter = document.querySelector('[data-customer-filter].active')?.dataset.customerFilter || 'all';
    renderCustomers('', categoryFilter);
  });
  
  // Sale Form
  safeAddListener('saleForm', 'submit', saveSale);
  
  const saleInstallments = document.getElementById('saleInstallments');
  if (saleInstallments) {
    saleInstallments.addEventListener('input', function() {
      const installmentsCount = Number(this.value);
      const amount = Number(document.getElementById('saleAmount')?.value || 0);
      const installmentAmountInput = document.getElementById('saleInstallmentAmount');
      
      if (installmentsCount > 0 && amount > 0 && installmentAmountInput) {
        const calculatedAmount = Math.ceil(amount / installmentsCount);
        installmentAmountInput.placeholder = `سيتم حسابه تلقائياً: ${formatMoney(calculatedAmount)}`;
      } else if (installmentAmountInput) {
        installmentAmountInput.placeholder = 'سيتم حسابه تلقائياً';
      }
    });
  }
  
  const saleAmount = document.getElementById('saleAmount');
  if (saleAmount) {
    saleAmount.addEventListener('input', function() {
      const installmentsCount = Number(document.getElementById('saleInstallments')?.value || 0);
      const amount = Number(this.value);
      const installmentAmountInput = document.getElementById('saleInstallmentAmount');
      
      if (installmentsCount > 0 && amount > 0 && installmentAmountInput) {
        const calculatedAmount = Math.ceil(amount / installmentsCount);
        installmentAmountInput.placeholder = `سيتم حسابه تلقائياً: ${formatMoney(calculatedAmount)}`;
      }
      updateContractText();
    });
  }
  
  // Contract Text Updates
  safeAddListener('saleCustomer', 'change', updateContractText);
  safeAddListener('saleProduct', 'input', updateContractText);
  safeAddListener('saleInstallments', 'input', updateContractText);
  safeAddListener('saleInstallmentAmount', 'input', updateContractText);
  safeAddListener('saleDueDate', 'change', updateContractText);
  
  // Payment Modal
  safeAddListener('closePaymentModal', 'click', () => {
    const modal = document.getElementById('paymentModal');
    if (modal) modal.classList.remove('open');
  });
  safeAddListener('paymentForm', 'submit', savePayment);
  
  // Sale Detail Modal
  safeAddListener('closeSaleDetailModal', 'click', () => {
    const modal = document.getElementById('saleDetailModal');
    if (modal) modal.classList.remove('open');
  });
  safeAddListener('printContract', 'click', printContract);
  
  const exportSalePDF = document.getElementById('exportSalePDF');
  if (exportSalePDF) {
    exportSalePDF.addEventListener('click', () => {
      if (!currentSaleForPrint) return;
      const sale = currentSaleForPrint;
      const customer = getCustomers().find(c => c.id === sale.customerId);
      const remaining = sale.totalAmount - (sale.paidAmount || 0);
      
      const printWindow = window.open('', '_blank');
      if (printWindow) {
        printWindow.document.write(`
          <!DOCTYPE html>
          <html lang="ar" dir="rtl">
          <head>
            <meta charset="UTF-8">
            <title>عقد البيع - ${escapeHtml(sale.product)}</title>
            <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              body {
                font-family: 'Tajawal', Arial, sans-serif;
                padding: 2rem;
                line-height: 1.8;
                color: #1e293b;
              }
              .contract-header {
                text-align: center;
                margin-bottom: 2rem;
                padding-bottom: 1rem;
                border-bottom: 3px solid #0d9488;
              }
              .contract-header h1 {
                font-size: 1.8rem;
                color: #0d9488;
                margin-bottom: 0.5rem;
              }
              .contract-text {
                background: #f0fdfa;
                padding: 1.5rem;
                border: 2px solid #0d9488;
                border-radius: 8px;
                margin: 2rem 0;
                white-space: pre-wrap;
                line-height: 2;
              }
            </style>
          </head>
          <body>
            <div class="contract-header">
              <h1>عقد بيع</h1>
              <p>رقم العقد: <strong>${escapeHtml(sale.id)}</strong></p>
              <p>تاريخ: ${formatDate(sale.date)}</p>
            </div>
            <div class="contract-text">${escapeHtml(sale.contractText || '—')}</div>
          </body>
          </html>
        `);
        printWindow.document.close();
      }
    });
  }
  
  // Edit Sale Modal
  safeAddListener('closeEditSaleModal', 'click', () => {
    const modal = document.getElementById('editSaleModal');
    if (modal) modal.classList.remove('open');
  });
  safeAddListener('editSaleForm', 'submit', saveEditSale);
  
  // Settings
  safeAddListener('settingsForm', 'submit', saveSettings);
  
  // Reports
  safeQueryAll('.period-btn', 'click', (e) => {
    document.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
    e.currentTarget.classList.add('active');
    if (e.currentTarget.dataset.period) {
      renderReports(e.currentTarget.dataset.period);
    }
  });
  
  safeAddListener('applyFilters', 'click', () => {
    advancedFilters = {
      dateFrom: document.getElementById('filterDateFrom')?.value || null,
      dateTo: document.getElementById('filterDateTo')?.value || null,
      amountMin: document.getElementById('filterAmountMin')?.value ? Number(document.getElementById('filterAmountMin').value) : null,
      amountMax: document.getElementById('filterAmountMax')?.value ? Number(document.getElementById('filterAmountMax').value) : null
    };
    const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
    const searchValue = document.getElementById('salesSearch')?.value || '';
    renderSalesList(searchValue, filter);
    toast('تم تطبيق الفلاتر');
  });
  
  safeAddListener('clearFilters', 'click', () => {
    const dateFrom = document.getElementById('filterDateFrom');
    const dateTo = document.getElementById('filterDateTo');
    const amountMin = document.getElementById('filterAmountMin');
    const amountMax = document.getElementById('filterAmountMax');
    
    if (dateFrom) dateFrom.value = '';
    if (dateTo) dateTo.value = '';
    if (amountMin) amountMin.value = '';
    if (amountMax) amountMax.value = '';
    
    advancedFilters = { dateFrom: null, dateTo: null, amountMin: null, amountMax: null };
    const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
    const searchValue = document.getElementById('salesSearch')?.value || '';
    renderSalesList(searchValue, filter);
    toast('تم مسح الفلاتر');
  });
  
  // Global Search
  const globalSearch = document.getElementById('globalSearch');
  if (globalSearch) {
    let searchTimeout;
    globalSearch.addEventListener('input', (e) => {
      clearTimeout(searchTimeout);
      const query = e.target.value.trim();
      searchTimeout = setTimeout(() => {
        performGlobalSearch(query);
      }, 300);
    });
  }
  
  // Sales Search
  const salesSearch = document.getElementById('salesSearch');
  if (salesSearch) {
    salesSearch.addEventListener('input', (e) => {
      const val = e.target.value;
      const clearBtn = document.getElementById('clearSalesSearch');
      if (clearBtn) clearBtn.style.display = val ? 'block' : 'none';
      const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
      renderSalesList(val, filter);
    });
  }
  
  safeAddListener('clearSalesSearch', 'click', () => {
    const search = document.getElementById('salesSearch');
    const clearBtn = document.getElementById('clearSalesSearch');
    if (search) search.value = '';
    if (clearBtn) clearBtn.style.display = 'none';
    const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
    renderSalesList('', filter);
  });
  
  // Filter Tabs
  safeQueryAll('.filter-tab', 'click', (e) => {
    document.querySelectorAll('.filter-tab').forEach(tab => tab.classList.remove('active'));
    e.currentTarget.classList.add('active');
    const filter = e.currentTarget.dataset.filter || 'all';
    const searchValue = document.getElementById('salesSearch')?.value || '';
    renderSalesList(searchValue, filter);
  });
  
  // Activity Filter
  safeQueryAll('[data-activity-filter]', 'click', (e) => {
    document.querySelectorAll('[data-activity-filter]').forEach(b => b.classList.remove('active'));
    e.currentTarget.classList.add('active');
    const filter = e.currentTarget.dataset.activityFilter || 'all';
    renderActivity(filter);
  });
  
  // Export/Import
  safeAddListener('exportData', 'click', exportData);
  safeAddListener('importData', 'click', importData);
  
  // External Debts
  safeAddListener('externalDebtForm', 'submit', saveExternalDebt);
  safeAddListener('addExternalTypeBtn', 'click', addExternalDebtTypeFromUI);
  safeAddListener('closeExternalDebtPaymentModal', 'click', () => {
    document.getElementById('externalDebtPaymentModal')?.classList.remove('open');
  });
  safeAddListener('externalDebtPaymentForm', 'submit', saveExternalDebtPayment);
  safeAddListener('closeExternalDebtDetailModal', 'click', () => {
    document.getElementById('externalDebtDetailModal')?.classList.remove('open');
  });
  safeAddListener('closeExternalDebtGroupModal', 'click', () => {
    document.getElementById('externalDebtGroupModal')?.classList.remove('open');
  });

  // Logout
  safeAddListener('logoutBtn', 'click', () => {
    try {
      if (window.auth) window.auth.logout();
    } catch (_) {}
    window.location.href = 'login.html';
  });
  
  // Debt Info Button
  const debtInfoBtn = document.getElementById('debtInfoBtn');
  if (debtInfoBtn) {
    debtInfoBtn.addEventListener('click', () => {
      const sales = getSales();
      const late = getLateSales();
      let totalDebts = 0;
      let lateDebts = 0;
      let activeDebts = 0;
      let externalDebtsRemaining = 0;
      let externalDebtsActiveCount = 0;
      
      sales.forEach(s => {
        const remaining = (s.totalAmount || 0) - (s.paidAmount || 0);
        if (remaining > 0) {
          totalDebts += remaining;
          if (getIsSaleLate(s)) {
            lateDebts += remaining;
          } else {
            activeDebts += remaining;
          }
        }
      });

      const externalDebts = getExternalDebts();
      externalDebts.forEach(d => {
        const rem = getExternalDebtRemaining(d);
        if (rem > 0) {
          externalDebtsRemaining += rem;
          externalDebtsActiveCount += 1;
        }
      });
      totalDebts += externalDebtsRemaining;
      
      const modal = document.createElement('div');
      modal.className = 'modal open';
      modal.innerHTML = `
        <div class="modal-content">
          <div class="modal-header">
            <h3>تفاصيل الديون</h3>
            <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
          </div>
          <div style="padding: 1.5rem;">
            <div class="debt-detail-item">
              <span class="debt-detail-label">إجمالي الديون المتبقية</span>
              <span class="debt-detail-value">${formatMoney(totalDebts)}</span>
            </div>
            <div class="debt-detail-item debt-detail-item--late">
              <span class="debt-detail-label">ديون متأخرة</span>
              <span class="debt-detail-value">${formatMoney(lateDebts)}</span>
            </div>
            <div class="debt-detail-item debt-detail-item--active">
              <span class="debt-detail-label">ديون نشطة</span>
              <span class="debt-detail-value">${formatMoney(activeDebts)}</span>
            </div>
            <div class="debt-detail-item" style="border-right: 3px solid var(--info);">
              <span class="debt-detail-label">ديون خارجية (متبقي)</span>
              <span class="debt-detail-value" style="color: var(--info-dark);">${formatMoney(externalDebtsRemaining)}</span>
            </div>
            <div class="debt-detail-item">
              <span class="debt-detail-label">عدد المبيعات المتأخرة</span>
              <span class="debt-detail-value">${late.length}</span>
            </div>
            <div class="debt-detail-item">
              <span class="debt-detail-label">عدد المبيعات النشطة</span>
              <span class="debt-detail-value">${sales.filter(s => {
                const rem = s.totalAmount - (s.paidAmount || 0);
                return rem > 0 && !getIsSaleLate(s);
              }).length}</span>
            </div>
            <div class="debt-detail-item">
              <span class="debt-detail-label">عدد الديون الخارجية النشطة</span>
              <span class="debt-detail-value">${externalDebtsActiveCount}</span>
            </div>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
      modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
      });
    });
  }
  
  // Modal close on outside click (delegated)
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
      e.target.classList.remove('open');
    }
  });
  
  console.log('Event listeners initialized successfully');
}

// ========== الإعدادات ==========
function getSettings() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.settings);
    const defaultSettings = { 
      lateDays: 30, 
      notifyOnLate: true, 
      darkMode: false,
      autoSave: false,
      showNotifications: true,
      itemsPerPage: 20,
      dateFormat: 'en-GB',
      browserNotifications: false,
      autoBackup: false
    };
    return data ? { ...defaultSettings, ...JSON.parse(data) } : defaultSettings;
  } catch {
    return { 
      lateDays: 30, 
      notifyOnLate: true, 
      darkMode: false,
      autoSave: false,
      showNotifications: true,
      itemsPerPage: 20,
      dateFormat: 'en-GB',
      browserNotifications: false,
      autoBackup: false
    };
  }
}

function setSettings(settings) {
  localStorage.setItem(STORAGE_KEYS.settings, JSON.stringify(settings));
  if (!cloudSyncApplying) {
    touchLocalUpdatedAt();
    scheduleCloudPush('settings');
  }
}

// ========== توليد ID فريد للبيع ==========
function generateSaleId() {
  const sales = getSales();
  const today = new Date();
  const dateStr = today.toISOString().split('T')[0].replace(/-/g, ''); // YYYYMMDD
  const prefix = 'SALE-' + dateStr + '-';
  
  // البحث عن آخر ID بنفس التاريخ
  const todaySales = sales.filter(s => s.id && s.id.startsWith(prefix));
  let maxNum = 0;
  
  todaySales.forEach(sale => {
    const match = sale.id.match(/-(\d+)$/);
    if (match) {
      const num = parseInt(match[1], 10);
      if (num > maxNum) maxNum = num;
    }
  });
  
  // إنشاء رقم تسلسلي جديد
  const nextNum = (maxNum + 1).toString().padStart(4, '0');
  return prefix + nextNum;
}

// ========== تخزين واسترجاع البيانات ==========
function getCustomers() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.customers);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

function setCustomers(arr) {
  localStorage.setItem(STORAGE_KEYS.customers, JSON.stringify(arr));
  if (!cloudSyncApplying) {
    touchLocalUpdatedAt();
    scheduleCloudPush('customers');
  }
}

function getSales() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.sales);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

function setSales(arr) {
  localStorage.setItem(STORAGE_KEYS.sales, JSON.stringify(arr));
  if (!cloudSyncApplying) {
    touchLocalUpdatedAt();
    scheduleCloudPush('sales');
  }
}

// ========== الديون الخارجية ==========
function getExternalDebtTypes() {
  const defaults = ['عام'];
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.externalDebtTypes);
    const arr = raw ? JSON.parse(raw) : null;
    if (!Array.isArray(arr)) return defaults;
    const cleaned = arr
      .map(x => (x || '').toString().trim())
      .filter(Boolean);
    return cleaned.length ? Array.from(new Set(cleaned)) : defaults;
  } catch {
    return defaults;
  }
}

function setExternalDebtTypes(arr) {
  const cleaned = (Array.isArray(arr) ? arr : [])
    .map(x => (x || '').toString().trim())
    .filter(Boolean);
  const unique = cleaned.length ? Array.from(new Set(cleaned)) : ['عام'];
  localStorage.setItem(STORAGE_KEYS.externalDebtTypes, JSON.stringify(unique));
  if (!cloudSyncApplying) {
    touchLocalUpdatedAt();
    scheduleCloudPush('externalDebtTypes');
  }
}

function getExternalDebts() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.externalDebts);
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function setExternalDebts(arr) {
  localStorage.setItem(STORAGE_KEYS.externalDebts, JSON.stringify(Array.isArray(arr) ? arr : []));
  if (!cloudSyncApplying) {
    touchLocalUpdatedAt();
    scheduleCloudPush('externalDebts');
  }
}

function getExternalDebtRemaining(d) {
  const total = Number(d?.totalAmount || 0);
  const paid = Number(d?.paidAmount || 0);
  const rem = total - paid;
  return rem > 0 ? rem : 0;
}

function getActivity() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.activity);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

function setActivity(arr) {
  localStorage.setItem(STORAGE_KEYS.activity, JSON.stringify(arr));
  if (!cloudSyncApplying) {
    touchLocalUpdatedAt();
    scheduleCloudPush('activity');
  }
}

function addActivity(type, text, meta = {}) {
  const list = getActivity();
  list.unshift({
    id: Date.now().toString(36) + Math.random().toString(36).slice(2),
    type,
    text,
    meta,
    date: new Date().toISOString()
  });
  // الاحتفاظ بآخر 500 حركة فقط
  const trimmed = list.slice(0, 500);
  setActivity(trimmed);
}

// ========== مساعدات ==========
function formatDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function formatDateOnly(value) {
  if (!value) return '—';
  const settings = getSettings();
  const fmt = settings?.dateFormat || 'en-GB';

  let d = new Date(value);
  if (Number.isNaN(d.getTime()) && typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    d = new Date(value + 'T00:00:00');
  }
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(fmt, { year: 'numeric', month: '2-digit', day: '2-digit' });
}

function formatMoney(n) {
  if (!n || isNaN(n) || n < 0) return '0 د.ع';
  return new Intl.NumberFormat('en-US').format(Number(n)) + ' د.ع';
}

function toast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ========== العملاء ==========
function renderCustomers(filter = '', categoryFilter = 'all') {
  const list = document.getElementById('customersList');
  let customers = getCustomers();
  const q = (filter || '').trim().toLowerCase();
  if (q) {
    customers = customers.filter(
      c =>
        (c.name && c.name.toLowerCase().includes(q)) ||
        (c.phone && c.phone.includes(q)) ||
        (c.address && c.address.toLowerCase().includes(q)) ||
        (c.notes && c.notes.toLowerCase().includes(q))
    );
  }
  // فلترة حسب التصنيف
  if (categoryFilter !== 'all') {
    customers = customers.filter(c => (c.category || 'normal') === categoryFilter);
  }
  if (customers.length === 0) {
    list.innerHTML = '<div class="empty-state visible">لا يوجد عملاء. أضف عميلاً من الزر أعلاه.</div>';
    return;
  }
  const categoryLabels = { normal: 'عادي', vip: 'مميز', problematic: 'مشاكل' };
  const categoryColors = { normal: '', vip: 'customer-vip', problematic: 'customer-problematic' };
  
  list.innerHTML = customers
    .map(
      c => {
        const categoryLabel = categoryLabels[c.category] || 'عادي';
        const categoryClass = categoryColors[c.category] || '';
        const customerSales = getSales().filter(s => s.customerId === c.id);
        const salesCount = customerSales.length;
        const totalSales = customerSales.reduce((sum, s) => sum + s.totalAmount, 0);
        const totalPaid = customerSales.reduce((sum, s) => sum + (s.paidAmount || 0), 0);
        const totalRemaining = totalSales - totalPaid;
        const lateSales = customerSales.filter(s => {
          const remaining = s.totalAmount - (s.paidAmount || 0);
          return remaining > 0 && getIsSaleLate(s);
        }).length;
        const completedSales = customerSales.filter(s => {
          const remaining = s.totalAmount - (s.paidAmount || 0);
          return remaining <= 0;
        }).length;
        const paymentRate = totalSales > 0 ? Math.round((totalPaid / totalSales) * 100) : 0;
        
        return `
    <div class="card customer-card-enhanced ${categoryClass}" data-customer-id="${c.id}">
      <div class="customer-card-header">
        <div class="customer-card-title-section">
          <div class="card-title">
            ${c.category === 'vip' ? '<span class="customer-icon customer-icon--vip">⭐</span>' : ''}
            ${c.category === 'problematic' ? '<span class="customer-icon customer-icon--problematic">⚠️</span>' : ''}
            <span class="customer-name">${escapeHtml(c.name)}</span>
            <span class="customer-badge customer-badge--${c.category || 'normal'}">${categoryLabel}</span>
          </div>
          <div class="card-meta">
            <span class="meta-item">📞 ${escapeHtml(c.phone)}</span>
            ${c.address ? `<span class="meta-item">📍 ${escapeHtml(c.address)}</span>` : ''}
          </div>
        </div>
      </div>
      ${c.notes ? `<div class="card-notes">📝 ${escapeHtml(c.notes)}</div>` : ''}
      <div class="customer-card-stats">
        <div class="stat-row">
          <div class="stat-item">
            <span class="stat-label">المبيعات</span>
            <span class="stat-value stat-value--primary">${salesCount}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">مكتملة</span>
            <span class="stat-value stat-value--success">${completedSales}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">متأخرة</span>
            <span class="stat-value stat-value--danger">${lateSales}</span>
          </div>
        </div>
        <div class="stat-row stat-row--amounts">
          <div class="stat-item stat-item--full">
            <span class="stat-label">الإجمالي</span>
            <span class="stat-value stat-value--total">${formatMoney(totalSales)}</span>
          </div>
        </div>
        <div class="customer-progress-section">
          <div class="progress-info">
            <span class="progress-label">نسبة السداد</span>
            <span class="progress-percentage">${paymentRate}%</span>
          </div>
          <div class="progress-bar customer-progress-bar">
            <div class="progress-bar__fill" style="width: ${paymentRate}%"></div>
          </div>
          <div class="progress-details">
            <span class="progress-paid">مدفوع: ${formatMoney(totalPaid)}</span>
            <span class="progress-remaining">متبقي: ${formatMoney(totalRemaining)}</span>
          </div>
        </div>
      </div>
      <div class="card-actions">
        <button class="btn btn-secondary btn-edit-customer" data-id="${c.id}">
          <span class="btn-icon">✏️</span>
          <span>تعديل</span>
        </button>
        <button class="btn btn-danger btn-delete-customer" data-id="${c.id}" data-name="${escapeHtml(c.name)}">
          <span class="btn-icon">🗑️</span>
          <span>حذف</span>
        </button>
      </div>
    </div>`;
      }
    )
    .join('');

  list.querySelectorAll('.btn-edit-customer').forEach(btn => {
    btn.addEventListener('click', () => openCustomerModal(btn.dataset.id));
  });
  list.querySelectorAll('.btn-delete-customer').forEach(btn => {
    btn.addEventListener('click', () => confirmDeleteCustomer(btn.dataset.id, btn.dataset.name));
  });
}

function openCustomerModal(id = null) {
  const modal = document.getElementById('customerModal');
  const form = document.getElementById('customerForm');
  const title = document.getElementById('customerModalTitle');
  form.reset();
  document.getElementById('customerId').value = id || '';
  title.textContent = id ? 'تعديل عميل' : 'إضافة عميل';
  if (id) {
    const c = getCustomers().find(x => x.id === id);
    if (c) {
      document.getElementById('customerName').value = c.name || '';
      document.getElementById('customerPhone').value = c.phone || '';
      document.getElementById('customerAddress').value = c.address || '';
      document.getElementById('customerNotes').value = c.notes || '';
      document.getElementById('customerCategory').value = c.category || 'normal';
    }
  } else {
    document.getElementById('customerCategory').value = 'normal';
  }
  modal.classList.add('open');
}

function saveCustomer(e) {
  e.preventDefault();
  const id = document.getElementById('customerId').value;
  const name = document.getElementById('customerName').value.trim();
  const phone = document.getElementById('customerPhone').value.trim();
  const address = document.getElementById('customerAddress').value.trim();
  const notes = document.getElementById('customerNotes').value.trim();
  const category = document.getElementById('customerCategory').value || 'normal';
  const customers = getCustomers();
  if (id) {
    const idx = customers.findIndex(c => c.id === id);
    if (idx !== -1) {
      customers[idx] = { ...customers[idx], name, phone, address, notes, category };
      setCustomers(customers);
      addActivity('customer', `تم تعديل بيانات العميل: ${name}`, { customerId: id });
      toast('تم تحديث بيانات العميل');
    }
  } else {
    const newId = 'c' + Date.now();
    customers.push({ id: newId, name, phone, address, notes, category });
    setCustomers(customers);
    addActivity('customer', `تمت إضافة عميل جديد: ${name}`, { customerId: newId });
    toast('تمت إضافة العميل بنجاح');
  }
  document.getElementById('customerModal').classList.remove('open');
  const categoryFilter = document.querySelector('[data-customer-filter].active')?.dataset.customerFilter || 'all';
  renderCustomers(document.getElementById('customerSearch').value, categoryFilter);
  renderDashboard();
  fillSaleCustomerSelect();
}

function escapeHtml(s) {
  if (!s) return '';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// ========== حذف العملاء ==========
function confirmDeleteCustomer(id, name) {
  if (confirm(`هل أنت متأكد من حذف العميل "${name}"؟\n\nسيتم حذف جميع المبيعات المرتبطة بهذا العميل أيضاً.`)) {
    deleteCustomer(id);
  }
}

function deleteCustomer(id) {
  const customers = getCustomers();
  const sales = getSales();
  const customer = customers.find(c => c.id === id);
  if (!customer) return;
  const filteredCustomers = customers.filter(c => c.id !== id);
  const filteredSales = sales.filter(s => s.customerId !== id);
  setCustomers(filteredCustomers);
  setSales(filteredSales);
  addActivity('customer', `تم حذف العميل: ${customer.name}`, { customerId: id });
  toast('تم حذف العميل وجميع مبيعاته', 'warning');
  const categoryFilter = document.querySelector('[data-customer-filter].active')?.dataset.customerFilter || 'all';
  renderCustomers(document.getElementById('customerSearch').value, categoryFilter);
  const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
  renderSalesList(document.getElementById('salesSearch')?.value || '', filter);
  renderDashboard();
  updateLateBadge();
}

// ========== حذف المبيعات ==========
function confirmDeleteSale(id, product) {
  if (confirm(`هل أنت متأكد من حذف البيع "${product}"؟\n\nسيتم حذف جميع الأقساط المرتبطة بهذا البيع.`)) {
    deleteSale(id);
  }
}

function deleteSale(id) {
  const sales = getSales();
  const sale = sales.find(s => s.id === id);
  if (!sale) return;
  const filtered = sales.filter(s => s.id !== id);
  setSales(filtered);
  addActivity('sale', `تم حذف البيع: ${sale.product} (${sale.customerName})`, { saleId: id });
  toast('تم حذف البيع', 'warning');
  const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
  renderSalesList(document.getElementById('salesSearch')?.value || '', filter);
  renderDashboard();
  renderLateList();
  updateLateBadge();
}

// ========== المبيعات ==========
function fillSaleCustomerSelect() {
  const select = document.getElementById('saleCustomer');
  const current = select.value;
  select.innerHTML = '<option value="">-- اختر العميل --</option>' + getCustomers().map(c => `<option value="${c.id}">${escapeHtml(c.name)} - ${escapeHtml(c.phone)}</option>`).join('');
  if (current) select.value = current;
}

// ========== توليد نص العقد القانوني ==========
function generateContractText(customer, product, totalAmount, paidAmount, remainingAmount, installmentsCount, dueDate, installmentAmount = 0) {
  const settings = getSettings();
  const lateDays = settings.lateDays || 30;
  const currentDate = new Date();
  const contractDate = dueDate ? new Date(dueDate) : currentDate;
  const dateArabic = contractDate.toLocaleDateString('ar-IQ', { year: 'numeric', month: 'long', day: 'numeric' });
  const dateEnglish = contractDate.toLocaleDateString('en-GB');
  
  const customerName = customer ? customer.name : '[اسم المشتري]';
  const customerPhone = customer ? customer.phone : '[رقم الهاتف]';
  const customerAddress = customer && customer.address ? customer.address : '[العنوان]';
  
  // توليد ID للعقد (سيتم استبداله عند الحفظ)
  const contractId = '[رقم العقد]';
  
  // حساب مبلغ القسط
  const calculatedInstallmentAmount = installmentAmount > 0 ? installmentAmount : (installmentsCount > 0 ? Math.ceil(totalAmount / installmentsCount) : 0);
  
  return `عقد بيع وشراء بالأقساط
رقم العقد: ${contractId}

إنه في يوم ${dateArabic} الموافق ${dateEnglish}، تم الاتفاق والتراضى بين:

الطرف الأول (البائع): شركة سوبرماكس
الطرف الثاني (المشتري): ${customerName}
رقم الهاتف: ${customerPhone}
العنوان: ${customerAddress}

أولاً: موضوع العقد
يتعهد الطرف الأول ببيع والطرف الثاني بشراء المنتج التالي: ${product}، بموجب الشروط والأحكام المذكورة أدناه.

ثانياً: المبلغ وطريقة الدفع
- المبلغ الإجمالي: ${formatMoney(totalAmount)}
${installmentsCount > 0 ? `- طريقة الدفع: على أقساط شهرية متساوية
- عدد الأقساط: ${installmentsCount} قسط شهري
- مبلغ كل قسط: ${formatMoney(calculatedInstallmentAmount)}
- تاريخ أول قسط: ${dueDate ? new Date(dueDate).toLocaleDateString('ar-IQ', { year: 'numeric', month: 'long', day: 'numeric' }) : 'سيتم تحديده لاحقاً'}` : '- طريقة الدفع: دفعة واحدة (نقداً) عند التسليم'}
- المبلغ المدفوع مقدماً: ${formatMoney(paidAmount)}
- المبلغ المتبقي: ${formatMoney(remainingAmount)}
${installmentsCount > 0 ? `- ملاحظة: يتم سداد الأقساط شهرياً في المواعيد المحددة وفقاً لجدول الأقساط المرفق` : ''}

ثالثاً: التزامات المشتري
1. يلتزم المشتري بسداد الأقساط في المواعيد المحددة دون تأخير.
2. في حالة التأخر عن سداد أي قسط لأكثر من ${lateDays} يوماً من تاريخ الاستحقاق، يحق للبائع:
   - المطالبة بسداد المبلغ المتبقي كاملاً دفعة واحدة
   - إضافة فوائد تأخيرية بنسبة 2% شهرياً على المبلغ المتأخر
   - اتخاذ الإجراءات القانونية اللازمة لاسترداد الحقوق بما في ذلك رفع الدعوى القضائية

رابعاً: التزامات البائع
1. يلتزم البائع بتسليم المنتج المتفق عليه بالشروط والمواصفات المذكورة.
2. يلتزم البائع بحفظ جميع البيانات والمستندات المتعلقة بهذا العقد.
3. يلتزم البائع بتسجيل جميع المدفوعات والأقساط في النظام الإلكتروني.

خامساً: أحكام عامة
1. هذا العقد ملزم قانونياً للطرفين ويمكن الاحتجاج به أمام الجهات القضائية المختصة.
2. جميع البيانات المذكورة في هذا العقد صحيحة ومسجلة في النظام الإلكتروني.
3. أي تعديل على هذا العقد يجب أن يكون كتابياً وموثقاً من الطرفين.
4. في حالة النزاع، يتم اللجوء إلى القضاء المختص في [المحافظة/المدينة].
5. يعتبر هذا العقد ساري المفعول من تاريخ التوقيع ويبقى نافذاً حتى سداد جميع المبالغ المستحقة.

سادساً: التوقيع
أقر الطرفان بقراءة وفهم جميع بنود هذا العقد والموافقة عليها، وتم التوقيع الإلكتروني والتسجيل في النظام بتاريخ ${dateArabic}.

ملاحظة: هذا العقد محفوظ إلكترونياً ويمكن طباعته والاحتجاج به قانونياً. جميع البيانات مسجلة في النظام ويمكن الرجوع إليها في أي وقت.`;
}

function saveSale(e) {
  e.preventDefault();
  const customerId = document.getElementById('saleCustomer').value;
  const product = document.getElementById('saleProduct').value.trim();
  const amount = Number(document.getElementById('saleAmount').value);
  const installmentsCount = Number(document.getElementById('saleInstallments').value) || 0;
  const installmentAmount = Number(document.getElementById('saleInstallmentAmount').value) || 0;
  const dueDate = document.getElementById('saleDueDate').value;
  const contractText = document.getElementById('saleContract').value.trim();
  if (!customerId || !product || !amount || amount < 1) {
    toast('يرجى تعبئة العميل ونوع المنتج والمبلغ', 'error');
    return;
  }
  const customer = getCustomers().find(c => c.id === customerId);
  const saleId = generateSaleId();
  
  // حساب جدول الأقساط
  const installmentsSchedule = [];
  if (installmentsCount > 0) {
    const calculatedInstallmentAmount = installmentAmount || Math.ceil(amount / installmentsCount);
    const startDate = dueDate ? new Date(dueDate) : new Date();
    
    for (let i = 0; i < installmentsCount; i++) {
      const installmentDate = new Date(startDate);
      installmentDate.setMonth(startDate.getMonth() + i);
      installmentsSchedule.push({
        number: i + 1,
        amount: i === installmentsCount - 1 ? amount - (calculatedInstallmentAmount * (installmentsCount - 1)) : calculatedInstallmentAmount,
        dueDate: installmentDate.toISOString(),
        paid: false,
        paidDate: null
      });
    }
  }
  
  // توليد نص العقد تلقائياً إذا لم يتم إدخال نص مخصص أو إذا كان النص يحتوي على قيم غير صحيحة
  let finalContractText = contractText;
  if (!contractText || contractText.trim() === '' || 
      contractText.includes('[اسم المشتري]') || 
      contractText.includes('[اسم المنتج]') ||
      contractText.includes('2 د.ع دينار عراقي') ||
      (contractText.includes('المبلغ الإجمالي:') && !contractText.includes(formatMoney(amount).split(' ')[0]))) {
    finalContractText = generateContractText(customer, product, amount, 0, amount, installmentsCount, dueDate, installmentAmount);
  }
  
  // استبدال رقم العقد في النص
  finalContractText = finalContractText.replace('[رقم العقد]', saleId);
  
  const sale = {
    id: saleId,
    customerId,
    customerName: customer ? customer.name : '',
    product,
    totalAmount: amount,
    paidAmount: 0,
    payments: [],
    contractText: finalContractText,
    installmentsCount: installmentsCount || 1,
    installmentsSchedule: installmentsSchedule,
    dueDate: dueDate || new Date().toISOString(),
    date: new Date().toISOString()
  };
  const sales = getSales();
  sales.unshift(sale);
  setSales(sales);
  addActivity('sale', `بيع جديد: ${product} للعميل ${customer ? customer.name : ''} - ${formatMoney(amount)}`, { saleId, customerId });
  toast('تم تسجيل البيع وحفظ العقد');
  document.getElementById('saleForm').reset();
  // إعادة تعيين نص العقد الافتراضي
  const defaultContract = generateContractText(null, '[اسم المنتج]', 0, 0, 0, 0, new Date(), 0);
  document.getElementById('saleContract').value = defaultContract;
  renderSalesList('', 'all');
  // تحديث حالة الأقساط القديمة بناءً على المدفوعات
  syncInstallmentsWithPayments();
  
  renderDashboard();
  updateLateBadge();
  renderUpcomingInstallments();
}

// ========== مزامنة حالة الأقساط مع المدفوعات ==========
function syncInstallmentsWithPayments() {
  const sales = getSales();
  let updated = false;
  
  sales.forEach(sale => {
    if (!sale.installmentsSchedule || sale.installmentsSchedule.length === 0) return;
    if (!sale.payments || sale.payments.length === 0) return;
    
    // حساب المبلغ المدفوع الإجمالي
    const totalPaid = sale.paidAmount || 0;
    
    // ترتيب الأقساط حسب التاريخ
    const sortedInstallments = sale.installmentsSchedule.map((inst, index) => ({
      ...inst,
      originalIndex: index
    })).sort((a, b) => {
      return new Date(a.dueDate) - new Date(b.dueDate);
    });
    
    let remainingPaid = totalPaid;
    
    // تحديث حالة الأقساط بناءً على المبلغ المدفوع
    for (let item of sortedInstallments) {
      if (remainingPaid <= 0) {
        // إذا لم يعد هناك مبلغ مدفوع، يجب أن يكون القسط غير مدفوع
        if (sale.installmentsSchedule[item.originalIndex].paid) {
          sale.installmentsSchedule[item.originalIndex].paid = false;
          updated = true;
        }
      } else if (remainingPaid >= item.amount) {
        // إذا كان المبلغ المدفوع يغطي القسط بالكامل
        if (!sale.installmentsSchedule[item.originalIndex].paid) {
          sale.installmentsSchedule[item.originalIndex].paid = true;
          updated = true;
        }
        remainingPaid -= item.amount;
      } else {
        // إذا كان المبلغ المدفوع أقل من مبلغ القسط، لا نحدّث القسط
        if (sale.installmentsSchedule[item.originalIndex].paid) {
          sale.installmentsSchedule[item.originalIndex].paid = false;
          updated = true;
        }
      }
    }
  });
  
  if (updated) {
    setSales(sales);
  }
}

// ========== عرض المبيعات + إضافة قسط ==========
function renderSalesList(filter = '', statusFilter = 'all') {
  const list = document.getElementById('salesList');
  let sales = getSales();
  const q = (filter || '').trim().toLowerCase();
  if (q) {
    sales = sales.filter(
      s =>
        (s.customerName && s.customerName.toLowerCase().includes(q)) ||
        (s.product && s.product.toLowerCase().includes(q)) ||
        (s.id && s.id.toLowerCase().includes(q))
    );
  }
  // فلتر حسب الحالة
  if (statusFilter !== 'all') {
    sales = sales.filter(s => {
      const remaining = s.totalAmount - (s.paidAmount || 0);
      const isPaid = remaining <= 0;
      const isLate = getIsSaleLate(s);
      if (statusFilter === 'completed') return isPaid;
      if (statusFilter === 'active') return !isPaid && !isLate;
      if (statusFilter === 'late') return isLate && !isPaid;
      return true;
    });
  }
  // فلترة متقدمة
  if (advancedFilters.dateFrom) {
    const fromDate = new Date(advancedFilters.dateFrom);
    sales = sales.filter(s => new Date(s.date) >= fromDate);
  }
  if (advancedFilters.dateTo) {
    const toDate = new Date(advancedFilters.dateTo);
    toDate.setHours(23, 59, 59, 999);
    sales = sales.filter(s => new Date(s.date) <= toDate);
  }
  if (advancedFilters.amountMin) {
    sales = sales.filter(s => s.totalAmount >= advancedFilters.amountMin);
  }
  if (advancedFilters.amountMax) {
    sales = sales.filter(s => s.totalAmount <= advancedFilters.amountMax);
  }
  if (sales.length === 0) {
    list.innerHTML = '<div class="empty-state visible">لا توجد مبيعات. سجّل بيعاً من صفحة "إضافة بيع".</div>';
    return;
  }
  list.innerHTML = sales
    .map(s => {
      const remaining = s.totalAmount - (s.paidAmount || 0);
      const isPaid = remaining <= 0;
      const isLate = getIsSaleLate(s);
      const pct = s.totalAmount > 0 ? Math.min(100, Math.round(((s.paidAmount || 0) / s.totalAmount) * 100)) : 0;
      return `
    <div class="card card--sale" data-sale-id="${s.id}">
      <div class="card-badges">
        ${isPaid ? '<span class="badge badge-success">مكتمل</span>' : ''}
        ${isLate && !isPaid ? '<span class="badge badge-danger">متأخر</span>' : ''}
        <span class="badge badge-info" style="background: #e0f2fe; color: #0369a1;">${escapeHtml(s.id)}</span>
      </div>
      <div class="card-title">${escapeHtml(s.product)}</div>
      <div class="card-meta">${escapeHtml(s.customerName)} · ${formatDate(s.date)}</div>
      <div class="card-progress">
        <div class="progress-bar">
          <div class="progress-bar__fill" style="width:${pct}%"></div>
        </div>
        <div class="card-progress__labels">
          <span>مدفوع ${formatMoney(s.paidAmount || 0)}</span>
          <span>متبقي ${formatMoney(remaining)}</span>
        </div>
      </div>
      <div class="card-actions">
        <button class="btn btn-secondary btn-view-sale" data-id="${s.id}">عرض العقد</button>
        <button class="btn btn-secondary btn-edit-sale" data-id="${s.id}">تعديل</button>
        ${!isPaid ? `<button class="btn btn-primary btn-add-payment" data-id="${s.id}">إضافة دفع قسط</button>` : ''}
        <button class="btn btn-danger btn-delete-sale" data-id="${s.id}" data-product="${escapeHtml(s.product)}">حذف</button>
      </div>
    </div>`;
    })
    .join('');

  list.querySelectorAll('.btn-add-payment').forEach(btn => {
    btn.addEventListener('click', () => openPaymentModal(btn.dataset.id));
  });
  list.querySelectorAll('.btn-view-sale').forEach(btn => {
    btn.addEventListener('click', () => openSaleDetailModal(btn.dataset.id));
  });
  list.querySelectorAll('.btn-delete-sale').forEach(btn => {
    btn.addEventListener('click', () => confirmDeleteSale(btn.dataset.id, btn.dataset.product));
  });
  list.querySelectorAll('.btn-edit-sale').forEach(btn => {
    btn.addEventListener('click', () => openEditSaleModal(btn.dataset.id));
  });
}

function getIsSaleLate(sale) {
  const settings = getSettings();
  const lateDays = settings.lateDays || 30;
  if (!sale.payments || sale.payments.length === 0) {
    const daysSinceSale = (Date.now() - new Date(sale.date).getTime()) / (1000 * 60 * 60 * 24);
    return daysSinceSale > lateDays;
  }
  const lastPayment = sale.payments[sale.payments.length - 1];
  const daysSinceLast = (Date.now() - new Date(lastPayment.date).getTime()) / (1000 * 60 * 60 * 24);
  return daysSinceLast > lateDays;
}

function openSaleDetailModal(saleId) {
  const sale = getSales().find(s => s.id === saleId);
  if (!sale) return;
  currentSaleForPrint = sale;
  const content = document.getElementById('saleDetailContent');
  const remaining = sale.totalAmount - (sale.paidAmount || 0);
  content.innerHTML = `
    <div class="sale-detail-body">
      <div class="sale-detail-row">
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">🆔</span>
          <div>
            <span class="sale-detail-info__label">رقم البيع</span>
            <span class="sale-detail-info__value" style="font-family: monospace; font-weight: 700; color: var(--primary);">${escapeHtml(sale.id)}</span>
          </div>
        </div>
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">👤</span>
          <div>
            <span class="sale-detail-info__label">العميل</span>
            <span class="sale-detail-info__value">${escapeHtml(sale.customerName)}</span>
          </div>
        </div>
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">📦</span>
          <div>
            <span class="sale-detail-info__label">المنتج</span>
            <span class="sale-detail-info__value">${escapeHtml(sale.product)}</span>
          </div>
        </div>
      </div>
      <div class="sale-detail-amounts">
        <div class="sale-detail-amount sale-detail-amount--total">
          <span class="sale-detail-amount__label">الإجمالي</span>
          <span class="sale-detail-amount__value">${formatMoney(sale.totalAmount)}</span>
        </div>
        <div class="sale-detail-amount sale-detail-amount--paid">
          <span class="sale-detail-amount__label">المدفوع</span>
          <span class="sale-detail-amount__value">${formatMoney(sale.paidAmount || 0)}</span>
        </div>
        <div class="sale-detail-amount sale-detail-amount--remaining">
          <span class="sale-detail-amount__label">المتبقي</span>
          <span class="sale-detail-amount__value">${formatMoney(remaining)}</span>
        </div>
      </div>
      <div class="sale-detail-section sale-detail-section--contract">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">📜</span>
          <h4>نص العقد (محفوظ قانونياً)</h4>
        </div>
        <div class="contract-box">${escapeHtml(sale.contractText || '—')}</div>
        <div class="sale-detail-date">
          <span class="sale-detail-date__label">تاريخ البيع</span>
          <span class="sale-detail-date__value">${formatDate(sale.date)}</span>
        </div>
      </div>
      ${(sale.installmentsSchedule && sale.installmentsSchedule.length > 0) ? `
      <div class="sale-detail-section">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">📅</span>
          <h4>جدول الأقساط المخطط</h4>
        </div>
        <div class="installments-schedule">
          <table class="schedule-table">
            <thead>
              <tr>
                <th>#</th>
                <th>المبلغ</th>
                <th>تاريخ الاستحقاق</th>
                <th>الحالة</th>
              </tr>
            </thead>
            <tbody>
              ${sale.installmentsSchedule.map((inst, i) => {
                const isPaid = inst.paid || false;
                const dueDate = new Date(inst.dueDate);
                const isOverdue = !isPaid && dueDate < new Date();
                return `
                <tr class="${isPaid ? 'schedule-row--paid' : isOverdue ? 'schedule-row--overdue' : ''}">
                  <td>${inst.number}</td>
                  <td>${formatMoney(inst.amount)}</td>
                  <td>${formatDate(inst.dueDate)}</td>
                  <td>
                    ${isPaid ? '<span class="schedule-status schedule-status--paid">✓ مدفوع</span>' : 
                      isOverdue ? '<span class="schedule-status schedule-status--overdue">⚠ متأخر</span>' : 
                      '<span class="schedule-status schedule-status--pending">⏳ قادم</span>'}
                  </td>
                </tr>
              `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>` : ''}
      ${(sale.payments && sale.payments.length) ? `
      <div class="sale-detail-section">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">📋</span>
          <h4>سجل الأقساط المدفوعة</h4>
        </div>
        <ul class="sale-detail-installments">
          ${sale.payments.map((p, i) => `
            <li class="sale-detail-installment">
              <span class="sale-detail-installment__num">${i + 1}</span>
              <span class="sale-detail-installment__amount">${formatMoney(p.amount)}</span>
              <span class="sale-detail-installment__note">${escapeHtml(p.note || 'قسط')}</span>
              <span class="sale-detail-installment__date">${formatDate(p.date)}</span>
            </li>
          `).join('')}
        </ul>
      </div>` : ''}
    </div>
  `;
  document.getElementById('saleDetailModal').classList.add('open');
}

function openPaymentModal(saleId) {
  const sale = getSales().find(s => s.id === saleId);
  if (!sale) return;
  const remaining = sale.totalAmount - (sale.paidAmount || 0);
  document.getElementById('paymentSaleId').value = saleId;
  document.getElementById('paymentSummary').innerHTML = `
    <div class="payment-summary__title">${escapeHtml(sale.product)} — ${escapeHtml(sale.customerName)}</div>
    <div class="payment-summary__row">
      <span class="payment-summary__label">الإجمالي</span>
      <span class="payment-summary__value">${formatMoney(sale.totalAmount)}</span>
    </div>
    <div class="payment-summary__row">
      <span class="payment-summary__label">المدفوع</span>
      <span class="payment-summary__value payment-summary__value--paid">${formatMoney(sale.paidAmount || 0)}</span>
    </div>
    <div class="payment-summary__row payment-summary__row--highlight">
      <span class="payment-summary__label">المتبقي</span>
      <span class="payment-summary__value payment-summary__value--remaining">${formatMoney(remaining)}</span>
    </div>
  `;
  document.getElementById('paymentAmount').value = '';
  document.getElementById('paymentAmount').max = remaining;
  document.getElementById('paymentAmount').placeholder = remaining;
  document.getElementById('paymentNote').value = '';
  document.getElementById('paymentModal').classList.add('open');
}

function savePayment(e) {
  e.preventDefault();
  const saleId = document.getElementById('paymentSaleId').value;
  const amount = Number(document.getElementById('paymentAmount').value);
  const note = document.getElementById('paymentNote').value.trim();
  if (!saleId || !amount || amount < 1) {
    toast('أدخل مبلغ الدفع', 'error');
    return;
  }
  const sales = getSales();
  const sale = sales.find(s => s.id === saleId);
  if (!sale) {
    toast('البيع غير موجود', 'error');
    return;
  }
  const remaining = sale.totalAmount - (sale.paidAmount || 0);
  if (amount > remaining) {
    toast('المبلغ أكبر من المتبقي', 'error');
    return;
  }
  const payment = {
    id: 'p' + Date.now(),
    amount,
    note: note || `قسط ${(sale.payments || []).length + 1}`,
    date: new Date().toISOString()
  };
  sale.payments = sale.payments || [];
  sale.payments.push(payment);
  sale.paidAmount = (sale.paidAmount || 0) + amount;
  
  // تحديث حالة الأقساط في installmentsSchedule
  if (sale.installmentsSchedule && sale.installmentsSchedule.length > 0) {
    let remainingPayment = amount;
    // ترتيب الأقساط حسب التاريخ (نحصل على الفهرس الأصلي)
    const installmentsWithIndex = sale.installmentsSchedule.map((inst, index) => ({
      ...inst,
      originalIndex: index
    })).sort((a, b) => {
      return new Date(a.dueDate) - new Date(b.dueDate);
    });
    
    // تحديث الأقساط غير المدفوعة بالترتيب
    for (let i = 0; i < installmentsWithIndex.length; i++) {
      if (remainingPayment <= 0) break;
      
      const item = installmentsWithIndex[i];
      if (!item.paid) {
        if (remainingPayment >= item.amount) {
          // إذا كان المبلغ المدفوع يغطي القسط بالكامل
          sale.installmentsSchedule[item.originalIndex].paid = true;
          remainingPayment -= item.amount;
        } else {
          // إذا كانت الدفعة أقل من مبلغ القسط، نخصمها من القسط الحالي
          sale.installmentsSchedule[item.originalIndex].amount -= remainingPayment;
          // إذا أصبح مبلغ القسط صفراً أو أقل، نجعله مدفوعاً
          if (sale.installmentsSchedule[item.originalIndex].amount <= 0) {
            sale.installmentsSchedule[item.originalIndex].paid = true;
            // إذا كان المبلغ سالباً، ننقله للقسط التالي
            const extraAmount = Math.abs(sale.installmentsSchedule[item.originalIndex].amount);
            sale.installmentsSchedule[item.originalIndex].amount = 0;
            remainingPayment = extraAmount;
          } else {
            remainingPayment = 0;
          }
        }
      }
    }
  }
  
  setSales(sales);
  addActivity('payment', `دفع قسط: ${formatMoney(amount)} - ${sale.product} (${sale.customerName})`, { saleId, paymentId: payment.id });
  toast('تم تسجيل الدفع');
  document.getElementById('paymentModal').classList.remove('open');
  const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
  renderSalesList(document.getElementById('salesSearch').value, filter);
  renderDashboard();
  renderLateList();
  renderUpcomingInstallments();
  updateLateBadge();
}

// ========== الحركات والنشاط ==========
function renderActivity(filter = 'all') {
  const list = document.getElementById('activityList');
  let items = getActivity();
  if (filter !== 'all') {
    items = items.filter(i => i.type === filter);
  }
  const icons = { sale: '💰', payment: '💵', customer: '👤' };
  const labels = { sale: 'بيع', payment: 'دفع', customer: 'عميل' };
  if (items.length === 0) {
    list.innerHTML = '<div class="empty-state visible">لا توجد حركات.</div>';
    return;
  }
  list.innerHTML = items
    .slice(0, 100)
    .map(
      i => `
    <div class="activity-item">
      <div class="activity-icon ${i.type}">${icons[i.type] || '•'}</div>
      <div class="activity-body">
        <div class="activity-text">${escapeHtml(i.text)}</div>
        <div class="activity-time">${formatDate(i.date)}</div>
      </div>
    </div>`
    )
    .join('');
}

// ========== المتأخرون ==========
function getLateSales() {
  return getSales().filter(s => {
    const remaining = s.totalAmount - (s.paidAmount || 0);
    return remaining > 0 && getIsSaleLate(s);
  });
}

function renderLateList() {
  const list = document.getElementById('lateList');
  const empty = document.getElementById('lateEmpty');
  const late = getLateSales();
  if (late.length === 0) {
    list.innerHTML = '';
    empty.classList.add('visible');
    return;
  }
  empty.classList.remove('visible');
  const customers = getCustomers();
  list.innerHTML = late
    .map(s => {
      const remaining = s.totalAmount - (s.paidAmount || 0);
      const cust = customers.find(c => c.id === s.customerId);
      const phone = cust ? cust.phone : '';
      return `
    <div class="card">
      <span class="badge badge-danger">متأخر عن السداد</span>
      <div class="card-title">${escapeHtml(s.customerName)}</div>
      <div class="card-meta">${escapeHtml(s.product)} · المتبقي: ${formatMoney(remaining)}</div>
      <div class="card-meta">${escapeHtml(phone)}</div>
      <div class="card-actions">
        <a href="#" class="btn btn-primary go-to-sale" data-id="${s.id}">إضافة دفع قسط</a>
      </div>
    </div>`;
    })
    .join('');

  list.querySelectorAll('.go-to-sale').forEach(btn => {
    btn.addEventListener('click', e => {
      e.preventDefault();
      showPage('sales-list');
      closeSidebar();
      setTimeout(() => {
        openPaymentModal(btn.dataset.id);
      }, 300);
    });
  });
}

function updateLateBadge() {
  const count = getLateSales().length;
  const badge = document.getElementById('lateBadge');
  badge.textContent = count + ' متأخر';
  badge.classList.toggle('has-late', count > 0);
}

// ========== الديون الخارجية (UI) ==========
function fillExternalDebtTypesSelect() {
  const select = document.getElementById('externalDebtType');
  if (!select) return;
  const current = select.value;
  const types = getExternalDebtTypes();
  select.innerHTML = types.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
  if (current && types.includes(current)) {
    select.value = current;
  }
}

function ensureExternalDebtDateDefault() {
  const input = document.getElementById('externalDebtDate');
  if (!input) return;
  if (!input.value) {
    input.value = new Date().toISOString().slice(0, 10);
  }
}

function renderExternalDebts() {
  fillExternalDebtTypesSelect();
  ensureExternalDebtDateDefault();

  const tbody = document.getElementById('externalDebtsTbody');
  const empty = document.getElementById('externalDebtsEmpty');
  const summaryEl = document.getElementById('externalDebtsSummary');
  const typeSummaryEl = document.getElementById('externalDebtsTypeSummary');
  if (!tbody || !empty) return;

  const list = getExternalDebts()
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  let totalRemaining = 0;
  list.forEach(d => {
    totalRemaining += getExternalDebtRemaining(d);
  });
  if (summaryEl) {
    summaryEl.textContent = `عدد: ${list.length} · المتبقي: ${formatMoney(totalRemaining)}`;
  }

  const attachPayButtons = (container) => {
    if (!container) return;
    container.querySelectorAll('.btn-pay-external-debt').forEach(btn => {
      btn.addEventListener('click', () => openExternalDebtPaymentModal(btn.dataset.id));
    });
    container.querySelectorAll('.btn-view-external-debt').forEach(btn => {
      btn.addEventListener('click', () => openExternalDebtDetailModal(btn.dataset.id));
    });
    container.querySelectorAll('.btn-view-external-debt-group').forEach(btn => {
      btn.addEventListener('click', (e) => {
        // إذا كان الزر داخل summary لا نريد فتح/إغلاق details
        try { e.preventDefault(); e.stopPropagation(); } catch (_) {}
        openExternalDebtGroupModal(btn.dataset.type, btn.dataset.kind);
      });
    });
    container.querySelectorAll('.btn-pay-external-debt-group').forEach(btn => {
      btn.addEventListener('click', (e) => {
        // إذا كان الزر داخل summary لا نريد فتح/إغلاق details
        try { e.preventDefault(); e.stopPropagation(); } catch (_) {}
        openExternalDebtGroupPay(btn.dataset.type, btn.dataset.kind);
      });
    });
  };

  // ملخص: بطاقة لكل (نوع + فئة) مع تفاصيل
  if (typeSummaryEl) {
    const map = {};
    list.forEach(d => {
      const t = (d.type || 'عام').toString().trim() || 'عام';
      const k = d.kind === 'loan' ? 'loan' : 'debt';
      const key = `${t}__${k}`;
      const total = Number(d.totalAmount || 0);
      const paid = Number(d.paidAmount || 0);
      const rem = getExternalDebtRemaining(d);
      if (!map[key]) map[key] = { type: t, kind: k, count: 0, total: 0, paid: 0, remaining: 0, items: [] };
      map[key].count += 1;
      map[key].total += total;
      map[key].paid += paid;
      map[key].remaining += rem;
      map[key].items.push(d);
    });
    const rows = Object.values(map)
      .filter(x => x.total > 0 || x.remaining > 0 || x.count > 0)
      .sort((a, b) => (b.remaining - a.remaining) || (b.total - a.total) || a.type.localeCompare(b.type));

    typeSummaryEl.innerHTML = rows.length
      ? rows.map(g => {
          const kindLabel = g.kind === 'loan' ? 'سلفة' : 'دين';
          const kindClass = g.kind === 'loan' ? 'debt-kind-badge--loan' : 'debt-kind-badge--debt';
          const itemsSorted = g.items
            .slice()
            .sort((a, b) => (getExternalDebtRemaining(b) - getExternalDebtRemaining(a)) || new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

          const detailsHtml = itemsSorted.map(item => {
            const debtDate = item.date || item.createdAt || '';
            const total = Number(item.totalAmount || 0);
            const paid = Number(item.paidAmount || 0);
            const remaining = getExternalDebtRemaining(item);
            const note = (item.note || '').toString().trim();
            return `
              <div class="debt-group-item">
                <div class="debt-group-item__main">
                  <div class="debt-group-item__line">
                    <span class="debt-group-item__date">${escapeHtml(formatDateOnly(debtDate))}</span>
                    <span class="debt-group-item__rem ${remaining > 0 ? 'debt-group-item__rem--pos' : 'debt-group-item__rem--zero'}">${formatMoney(remaining)}</span>
                  </div>
                  ${note ? `<div class="debt-group-item__note">${escapeHtml(note)}</div>` : ''}
                  <div class="debt-group-item__sub">
                    <span>إجمالي: ${formatMoney(total)}</span>
                    <span>مدفوع: ${formatMoney(paid)}</span>
                  </div>
                </div>
                <div class="debt-group-item__action">
                  <button class="btn btn-secondary btn-sm btn-view-external-debt" data-id="${escapeHtml(item.id)}">تفاصيل</button>
                  ${remaining > 0
                    ? `<button class="btn btn-primary btn-sm btn-pay-external-debt" data-id="${escapeHtml(item.id)}">سداد</button>`
                    : `<span class="badge badge-success">مكتمل</span>`
                  }
                </div>
              </div>
            `;
          }).join('');

          return `
            <details class="debt-group">
              <summary class="debt-group__summary">
                <div class="debt-group__title">
                  <span class="debt-group__name">${escapeHtml(g.type)}</span>
                  <span class="debt-kind-badge ${kindClass}">${kindLabel}</span>
                </div>
                <div class="debt-group__meta">
                  <span class="debt-group__count">${g.count} سجل</span>
                  <span class="debt-group__remaining">متبقي: ${formatMoney(g.remaining)}</span>
                  <button type="button" class="btn btn-secondary btn-sm btn-view-external-debt-group" data-type="${escapeHtml(g.type)}" data-kind="${escapeHtml(g.kind)}">تفاصيل الفئة</button>
                  ${g.remaining > 0
                    ? `<button type="button" class="btn btn-primary btn-sm btn-pay-external-debt-group" data-type="${escapeHtml(g.type)}" data-kind="${escapeHtml(g.kind)}">سداد كامل</button>`
                    : ''
                  }
                </div>
              </summary>
              <div class="debt-group__body">
                <div class="debt-group__totals">
                  <span>إجمالي: <strong>${formatMoney(g.total)}</strong></span>
                  <span>مدفوع: <strong>${formatMoney(g.paid)}</strong></span>
                </div>
                <div class="debt-group__list">
                  ${detailsHtml || '<div class="form-hint">لا توجد تفاصيل.</div>'}
                </div>
              </div>
            </details>
          `;
        }).join('')
      : '';

    attachPayButtons(typeSummaryEl);
  }

  if (list.length === 0) {
    tbody.innerHTML = '';
    empty.classList.add('visible');
    if (typeSummaryEl) typeSummaryEl.innerHTML = '';
    return;
  }

  empty.classList.remove('visible');
  tbody.innerHTML = list.map(d => {
    const debtDate = d.date || d.createdAt || '';
    const total = Number(d.totalAmount || 0);
    const paid = Number(d.paidAmount || 0);
    const remaining = getExternalDebtRemaining(d);
    const kind = d.kind === 'loan' ? 'سلفة' : 'دين';
    const kindClass = d.kind === 'loan' ? 'debt-kind-badge--loan' : 'debt-kind-badge--debt';
    const remainingClass = remaining <= 0 ? 'debt-remaining--zero' : 'debt-remaining--pos';
    const note = (d.note || '').toString().trim();

    return `
      <tr data-external-debt-id="${escapeHtml(d.id)}">
        <td data-label="التاريخ" style="white-space: nowrap;">${escapeHtml(formatDateOnly(debtDate))}</td>
        <td data-label="النوع">
          <strong class="external-debt-type">${escapeHtml(d.type || 'عام')}</strong>
          ${note ? `<div class="form-hint external-debt-note">${escapeHtml(note)}</div>` : ''}
        </td>
        <td data-label="الفئة"><span class="debt-kind-badge ${kindClass}">${kind}</span></td>
        <td data-label="الإجمالي">${formatMoney(total)}</td>
        <td data-label="المدفوع">${formatMoney(paid)}</td>
        <td data-label="المتبقي" class="debt-remaining ${remainingClass}">${formatMoney(remaining)}</td>
        <td data-label="إجراء">
          <button class="btn btn-secondary btn-sm btn-view-external-debt" data-id="${escapeHtml(d.id)}">تفاصيل</button>
          ${remaining > 0
            ? `<button class="btn btn-primary btn-sm btn-pay-external-debt" data-id="${escapeHtml(d.id)}">سداد</button>`
            : `<span class="badge badge-success">مكتمل</span>`
          }
        </td>
      </tr>
    `;
  }).join('');

  attachPayButtons(tbody);
}

function addExternalDebtTypeFromUI() {
  const input = document.getElementById('externalNewType');
  if (!input) return;
  const name = (input.value || '').toString().trim();
  if (!name) {
    toast('أدخل اسم النوع', 'error');
    return;
  }
  const types = getExternalDebtTypes();
  if (types.includes(name)) {
    toast('هذا النوع موجود مسبقاً', 'warning');
    input.value = '';
    return;
  }
  setExternalDebtTypes([name, ...types]);
  input.value = '';
  fillExternalDebtTypesSelect();
  const select = document.getElementById('externalDebtType');
  if (select) select.value = name;
  toast('تمت إضافة النوع');
  renderExternalDebts();
}

function saveExternalDebt(e) {
  e.preventDefault();
  const kind = document.querySelector('input[name="externalKind"]:checked')?.value || 'debt';
  const type = document.getElementById('externalDebtType')?.value || 'عام';
  const date = (document.getElementById('externalDebtDate')?.value || '').toString().trim();
  const amount = Number(document.getElementById('externalDebtAmount')?.value || 0);
  const note = (document.getElementById('externalDebtNote')?.value || '').toString().trim();

  if (!type) {
    toast('اختر نوع الدين', 'error');
    return;
  }
  if (!date) {
    toast('اختر التاريخ', 'error');
    return;
  }
  if (!amount || amount < 1) {
    toast('أدخل مبلغ صحيح', 'error');
    return;
  }

  const debt = {
    id: 'ed_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    kind: (kind === 'loan') ? 'loan' : 'debt',
    type,
    date, // YYYY-MM-DD
    totalAmount: amount,
    paidAmount: 0,
    payments: [],
    note,
    createdAt: new Date().toISOString()
  };

  const list = getExternalDebts();
  list.unshift(debt);
  setExternalDebts(list);

  addActivity('debt', `دين خارجي جديد: ${type} (${debt.kind === 'loan' ? 'سلفة' : 'دين'}) - ${formatMoney(amount)}`, { externalDebtId: debt.id });
  toast('تمت إضافة الدين الخارجي');

  // reset
  const form = document.getElementById('externalDebtForm');
  if (form) form.reset();
  fillExternalDebtTypesSelect();
  ensureExternalDebtDateDefault();

  renderExternalDebts();
  renderDashboard();
}

function openExternalDebtPaymentModal(externalDebtId) {
  const modal = document.getElementById('externalDebtPaymentModal');
  const debt = getExternalDebts().find(d => d.id === externalDebtId);
  if (!modal || !debt) return;

  const remaining = getExternalDebtRemaining(debt);
  if (remaining <= 0) {
    toast('هذا الدين مكتمل', 'warning');
    return;
  }

  document.getElementById('externalDebtPaymentId').value = externalDebtId;
  const kind = debt.kind === 'loan' ? 'سلفة' : 'دين';

  const summary = document.getElementById('externalDebtPaymentSummary');
  if (summary) {
    summary.innerHTML = `
      <div class="payment-summary__title">${escapeHtml(debt.type || 'عام')} — ${kind}</div>
      <div class="payment-summary__row">
        <span class="payment-summary__label">التاريخ</span>
        <span class="payment-summary__value">${escapeHtml(formatDateOnly(debt.date || debt.createdAt || ''))}</span>
      </div>
      <div class="payment-summary__row">
        <span class="payment-summary__label">الإجمالي</span>
        <span class="payment-summary__value">${formatMoney(debt.totalAmount || 0)}</span>
      </div>
      <div class="payment-summary__row">
        <span class="payment-summary__label">المدفوع</span>
        <span class="payment-summary__value payment-summary__value--paid">${formatMoney(debt.paidAmount || 0)}</span>
      </div>
      <div class="payment-summary__row payment-summary__row--highlight">
        <span class="payment-summary__label">المتبقي</span>
        <span class="payment-summary__value payment-summary__value--remaining">${formatMoney(remaining)}</span>
      </div>
    `;
  }

  const amountInput = document.getElementById('externalDebtPaymentAmount');
  if (amountInput) {
    amountInput.value = '';
    amountInput.max = remaining;
    amountInput.placeholder = remaining;
  }
  const noteInput = document.getElementById('externalDebtPaymentNote');
  if (noteInput) noteInput.value = '';

  modal.classList.add('open');
}

function openExternalDebtDetailModal(externalDebtId) {
  const debt = getExternalDebts().find(d => d.id === externalDebtId);
  if (!debt) {
    toast('الدين غير موجود', 'error');
    return;
  }

  const modal = document.getElementById('externalDebtDetailModal');
  const content = document.getElementById('externalDebtDetailContent');
  if (!modal || !content) return;

  const kindLabel = debt.kind === 'loan' ? 'سلفة' : 'دين';
  const total = Number(debt.totalAmount || 0);
  const paid = Number(debt.paidAmount || 0);
  const remaining = getExternalDebtRemaining(debt);
  const date = debt.date || debt.createdAt || '';
  const note = (debt.note || '').toString().trim();

  const payments = Array.isArray(debt.payments) ? debt.payments.slice() : [];
  payments.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));

  content.innerHTML = `
    <div class="sale-detail-body">
      <div class="sale-detail-row">
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">📅</span>
          <div>
            <span class="sale-detail-info__label">التاريخ</span>
            <span class="sale-detail-info__value">${escapeHtml(formatDateOnly(date))}</span>
          </div>
        </div>
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">🏷️</span>
          <div>
            <span class="sale-detail-info__label">النوع</span>
            <span class="sale-detail-info__value">${escapeHtml(debt.type || 'عام')}</span>
          </div>
        </div>
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">📌</span>
          <div>
            <span class="sale-detail-info__label">الفئة</span>
            <span class="sale-detail-info__value">${escapeHtml(kindLabel)}</span>
          </div>
        </div>
      </div>

      <div class="sale-detail-amounts">
        <div class="sale-detail-amount sale-detail-amount--total">
          <span class="sale-detail-amount__label">الإجمالي</span>
          <span class="sale-detail-amount__value">${formatMoney(total)}</span>
        </div>
        <div class="sale-detail-amount sale-detail-amount--paid">
          <span class="sale-detail-amount__label">المدفوع</span>
          <span class="sale-detail-amount__value">${formatMoney(paid)}</span>
        </div>
        <div class="sale-detail-amount sale-detail-amount--remaining">
          <span class="sale-detail-amount__label">المتبقي</span>
          <span class="sale-detail-amount__value">${formatMoney(remaining)}</span>
        </div>
      </div>

      ${note ? `
      <div class="sale-detail-section sale-detail-section--contract">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">📝</span>
          <h4>ملاحظة</h4>
        </div>
        <div class="contract-box">${escapeHtml(note)}</div>
      </div>
      ` : ''}

      <div class="sale-detail-section">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">💵</span>
          <h4>السداد</h4>
        </div>
        ${remaining > 0 ? `
          <button class="btn btn-primary btn-block" id="externalDebtDetailPayBtn">سداد الآن</button>
        ` : `
          <div class="empty-state visible" style="margin: 0;">الدين مكتمل ✓</div>
        `}
      </div>

      <div class="sale-detail-section">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">📋</span>
          <h4>سجل السدادات</h4>
        </div>
        ${payments.length ? `
          <ul class="sale-detail-installments">
            ${payments.map((p, i) => `
              <li class="sale-detail-installment">
                <span class="sale-detail-installment__num">${i + 1}</span>
                <span class="sale-detail-installment__amount">${formatMoney(p.amount || 0)}</span>
                <span class="sale-detail-installment__note">${escapeHtml(p.note || 'سداد')}</span>
                <span class="sale-detail-installment__date">${escapeHtml(formatDate(p.date || ''))}</span>
              </li>
            `).join('')}
          </ul>
        ` : `<div class="empty-state visible" style="margin: 0;">لا توجد سدادات بعد.</div>`}
      </div>
    </div>
  `;

  modal.classList.add('open');

  const payBtn = document.getElementById('externalDebtDetailPayBtn');
  payBtn?.addEventListener('click', () => {
    modal.classList.remove('open');
    openExternalDebtPaymentModal(externalDebtId);
  });
}

function openExternalDebtGroupModal(type, kind) {
  const modal = document.getElementById('externalDebtGroupModal');
  const content = document.getElementById('externalDebtGroupContent');
  if (!modal || !content) return;

  const safeType = (type || 'عام').toString().trim() || 'عام';
  const safeKind = (kind === 'loan') ? 'loan' : 'debt';
  const kindLabel = safeKind === 'loan' ? 'سلفة' : 'دين';

  const list = getExternalDebts()
    .filter(d => (String(d.type || 'عام').trim() || 'عام') === safeType && ((d.kind === 'loan') ? 'loan' : 'debt') === safeKind)
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  let total = 0, paid = 0, remaining = 0;
  list.forEach(d => {
    total += Number(d.totalAmount || 0);
    paid += Number(d.paidAmount || 0);
    remaining += getExternalDebtRemaining(d);
  });

  content.innerHTML = `
    <div class="sale-detail-body">
      <div class="sale-detail-row">
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">🏷️</span>
          <div>
            <span class="sale-detail-info__label">النوع</span>
            <span class="sale-detail-info__value">${escapeHtml(safeType)}</span>
          </div>
        </div>
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">📌</span>
          <div>
            <span class="sale-detail-info__label">الفئة</span>
            <span class="sale-detail-info__value">${escapeHtml(kindLabel)}</span>
          </div>
        </div>
        <div class="sale-detail-info">
          <span class="sale-detail-info__icon">🧾</span>
          <div>
            <span class="sale-detail-info__label">عدد السجلات</span>
            <span class="sale-detail-info__value">${list.length}</span>
          </div>
        </div>
      </div>

      <div class="sale-detail-amounts">
        <div class="sale-detail-amount sale-detail-amount--total">
          <span class="sale-detail-amount__label">الإجمالي</span>
          <span class="sale-detail-amount__value">${formatMoney(total)}</span>
        </div>
        <div class="sale-detail-amount sale-detail-amount--paid">
          <span class="sale-detail-amount__label">المدفوع</span>
          <span class="sale-detail-amount__value">${formatMoney(paid)}</span>
        </div>
        <div class="sale-detail-amount sale-detail-amount--remaining">
          <span class="sale-detail-amount__label">المتبقي</span>
          <span class="sale-detail-amount__value">${formatMoney(remaining)}</span>
        </div>
      </div>

      <div class="sale-detail-section">
        <div class="sale-detail-section__head">
          <span class="sale-detail-section__icon">📋</span>
          <h4>الجدول</h4>
        </div>
        <div class="table-wrap" style="max-height:none; overflow: auto;">
          <table class="data-table" aria-label="جدول الفئة">
            <thead>
              <tr>
                <th>التاريخ</th>
                <th>ملاحظة</th>
                <th>الإجمالي</th>
                <th>المدفوع</th>
                <th>المتبقي</th>
                <th>إجراء</th>
              </tr>
            </thead>
            <tbody>
              ${list.map(d => {
                const debtDate = d.date || d.createdAt || '';
                const t = Number(d.totalAmount || 0);
                const p = Number(d.paidAmount || 0);
                const r = getExternalDebtRemaining(d);
                const note = (d.note || '').toString().trim();
                return `
                  <tr>
                    <td data-label="التاريخ">${escapeHtml(formatDateOnly(debtDate))}</td>
                    <td data-label="ملاحظة">${note ? escapeHtml(note) : '—'}</td>
                    <td data-label="الإجمالي">${formatMoney(t)}</td>
                    <td data-label="المدفوع">${formatMoney(p)}</td>
                    <td data-label="المتبقي" class="debt-remaining ${r > 0 ? 'debt-remaining--pos' : 'debt-remaining--zero'}">${formatMoney(r)}</td>
                    <td data-label="إجراء">
                      <button class="btn btn-secondary btn-sm btn-view-external-debt" data-id="${escapeHtml(d.id)}">تفاصيل</button>
                      ${r > 0
                        ? `<button class="btn btn-primary btn-sm btn-pay-external-debt" data-id="${escapeHtml(d.id)}">سداد</button>`
                        : `<span class="badge badge-success">مكتمل</span>`
                      }
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
        ${list.length === 0 ? `<div class="empty-state visible" style="margin: 0.75rem 0 0;">لا توجد سجلات.</div>` : ''}
      </div>
    </div>
  `;

  modal.classList.add('open');

  // ربط الأزرار داخل النافذة
  content.querySelectorAll('.btn-pay-external-debt').forEach(btn => {
    btn.addEventListener('click', () => {
      modal.classList.remove('open');
      openExternalDebtPaymentModal(btn.dataset.id);
    });
  });
  content.querySelectorAll('.btn-view-external-debt').forEach(btn => {
    btn.addEventListener('click', () => openExternalDebtDetailModal(btn.dataset.id));
  });
}

function openExternalDebtGroupPay(type, kind) {
  const safeType = (type || 'عام').toString().trim() || 'عام';
  const safeKind = (kind === 'loan') ? 'loan' : 'debt';

  const all = getExternalDebts();
  const target = all
    .filter(d => (String(d.type || 'عام').trim() || 'عام') === safeType && ((d.kind === 'loan') ? 'loan' : 'debt') === safeKind);

  const payable = target
    .map(d => ({ d, rem: getExternalDebtRemaining(d) }))
    .filter(x => x.rem > 0);

  const totalRemaining = payable.reduce((sum, x) => sum + x.rem, 0);

  if (!totalRemaining || totalRemaining <= 0) {
    toast('لا يوجد متبقي للسداد في هذه الفئة', 'info');
    return;
  }

  const nowIso = new Date().toISOString();
  const base = Date.now().toString(36);
  const note = `سداد كامل للفئة: ${safeType} (${safeKind === 'loan' ? 'سلفة' : 'دين'})`;

  payable.forEach((x, idx) => {
    const debt = x.d;
    const amount = x.rem;
    const payment = {
      id: 'edp_' + base + '_' + idx,
      amount,
      note,
      date: nowIso
    };
    debt.payments = debt.payments || [];
    debt.payments.push(payment);
    debt.paidAmount = Number(debt.paidAmount || 0) + amount;
  });

  setExternalDebts(all);
  addActivity('payment', `سداد كامل لفئة خارجية: ${safeType} - ${formatMoney(totalRemaining)}`, { externalDebtType: safeType, externalDebtKind: safeKind, amount: totalRemaining });
  toast(`تم سداد كامل المتبقي: ${formatMoney(totalRemaining)}`);
  renderExternalDebts();
  renderDashboard();
}

function saveExternalDebtPayment(e) {
  e.preventDefault();
  const externalDebtId = document.getElementById('externalDebtPaymentId')?.value;
  const amount = Number(document.getElementById('externalDebtPaymentAmount')?.value || 0);
  const note = (document.getElementById('externalDebtPaymentNote')?.value || '').toString().trim();
  if (!externalDebtId || !amount || amount < 1) {
    toast('أدخل مبلغ السداد', 'error');
    return;
  }

  const list = getExternalDebts();
  const debt = list.find(d => d.id === externalDebtId);
  if (!debt) {
    toast('الدين غير موجود', 'error');
    return;
  }

  const remaining = getExternalDebtRemaining(debt);
  if (amount > remaining) {
    toast('المبلغ أكبر من المتبقي', 'error');
    return;
  }

  const payment = {
    id: 'edp_' + Date.now().toString(36),
    amount,
    note: note || 'سداد',
    date: new Date().toISOString()
  };
  debt.payments = debt.payments || [];
  debt.payments.push(payment);
  debt.paidAmount = Number(debt.paidAmount || 0) + amount;

  setExternalDebts(list);
  addActivity('payment', `سداد دين خارجي: ${formatMoney(amount)} - ${debt.type || 'عام'}`, { externalDebtId });
  toast('تم تسجيل السداد');

  document.getElementById('externalDebtPaymentModal')?.classList.remove('open');
  renderExternalDebts();
  renderDashboard();
}

// ========== لوحة التحكم ==========
function renderDashboard() {
  const customers = getCustomers();
  const sales = getSales();
  const late = getLateSales();
  const externalDebts = getExternalDebts();
  let collected = 0;
  let totalDebts = 0;
  let totalAmount = 0;
  sales.forEach(s => {
    collected += s.paidAmount || 0;
    totalAmount += s.totalAmount || 0;
    totalDebts += (s.totalAmount || 0) - (s.paidAmount || 0);
  });
  // إضافة الديون الخارجية (المتبقي)
  externalDebts.forEach(d => {
    totalDebts += getExternalDebtRemaining(d);
  });
  document.getElementById('statCustomers').textContent = new Intl.NumberFormat('en-US').format(customers.length);
  document.getElementById('statSales').textContent = new Intl.NumberFormat('en-US').format(sales.length);
  document.getElementById('statLate').textContent = new Intl.NumberFormat('en-US').format(late.length);
  document.getElementById('statCollected').textContent = new Intl.NumberFormat('en-US').format(collected);
  document.getElementById('statTotalDebts').textContent = formatMoney(totalDebts);
  
  // عرض الأقساط القادمة
  renderUpcomingInstallments();
  
  // رسم بياني
  const paidPercent = totalAmount > 0 ? Math.round((collected / totalAmount) * 100) : 0;
  document.getElementById('chartPaid').style.width = paidPercent + '%';
  document.getElementById('chartPaidAmount').textContent = formatMoney(collected);
  document.getElementById('chartRemainingAmount').textContent = formatMoney(totalDebts);
  const chartPercentage = document.getElementById('chartPercentage');
  if (chartPercentage) {
    chartPercentage.textContent = paidPercent + '%';
  }
  
  // إحصائيات إضافية
  let totalPayments = 0;
  sales.forEach(s => {
    if (s.payments) totalPayments += s.payments.length;
  });
  const avgSaleAmount = sales.length > 0 ? Math.round(totalAmount / sales.length) : 0;
  const completionRate = sales.length > 0 ? Math.round((sales.filter(s => {
    const rem = s.totalAmount - (s.paidAmount || 0);
    return rem <= 0;
  }).length / sales.length) * 100) : 0;
  
  // إحصائيات هذا الشهر
  const now = new Date();
  const currentMonth = now.getMonth();
  const currentYear = now.getFullYear();
  const monthlySales = sales.filter(s => {
    const saleDate = new Date(s.date);
    return saleDate.getMonth() === currentMonth && saleDate.getFullYear() === currentYear;
  });
  let monthlyTotal = 0, monthlyPaid = 0;
  monthlySales.forEach(s => {
    monthlyTotal += s.totalAmount || 0;
    monthlyPaid += s.paidAmount || 0;
  });
  
  // تحديث الإحصائيات الإضافية إذا كانت موجودة
  const extraStats = document.getElementById('extraStats');
  if (extraStats) {
    extraStats.innerHTML = `
      <div class="extra-stat">
        <span class="extra-stat__label">متوسط قيمة البيع</span>
        <span class="extra-stat__value">${formatMoney(avgSaleAmount)}</span>
      </div>
      <div class="extra-stat">
        <span class="extra-stat__label">إجمالي الأقساط</span>
        <span class="extra-stat__value">${totalPayments}</span>
      </div>
      <div class="extra-stat">
        <span class="extra-stat__label">نسبة الإتمام</span>
        <span class="extra-stat__value">${completionRate}%</span>
      </div>
      <div class="extra-stat">
        <span class="extra-stat__label">مبيعات هذا الشهر</span>
        <span class="extra-stat__value">${monthlySales.length}</span>
      </div>
      <div class="extra-stat">
        <span class="extra-stat__label">محصّل هذا الشهر</span>
        <span class="extra-stat__value">${formatMoney(monthlyPaid)}</span>
      </div>
      <div class="extra-stat">
        <span class="extra-stat__label">نسبة التحصيل</span>
        <span class="extra-stat__value">${totalAmount > 0 ? Math.round((collected / totalAmount) * 100) : 0}%</span>
      </div>
    `;
  }
}

// ========== التنقل ==========
function showPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  const page = document.getElementById('page-' + pageId);
  const link = document.querySelector(`.nav-link[data-page="${pageId}"]`);
  if (page) page.classList.add('active');
  if (link) link.classList.add('active');
  if (pageId === 'customers') {
    renderCustomers(document.getElementById('customerSearch').value);
  } else if (pageId === 'sales') {
    fillSaleCustomerSelect();
  } else if (pageId === 'sales-list') {
    const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
    renderSalesList(document.getElementById('salesSearch').value, filter);
  } else if (pageId === 'activity') {
    renderActivity(document.querySelector('.filter-btn.active')?.dataset.filter || 'all');
  } else if (pageId === 'notifications') {
    renderLateList();
  } else if (pageId === 'reports') {
    renderReports(currentReportPeriod);
    renderCharts(currentReportPeriod);
  } else if (pageId === 'external-debts') {
    renderExternalDebts();
  } else if (pageId === 'settings') {
    renderSettings();
  } else if (pageId === 'dashboard') {
    renderDashboard();
    renderUpcomingInstallments();
  }
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
}

// ========== الربط ==========
// جميع event listeners تم نقلها إلى initEventListeners() التي يتم استدعاؤها من initApp()

// تحديث نص العقد تلقائياً عند تغيير البيانات
function updateContractText() {
  const customerId = document.getElementById('saleCustomer')?.value;
  const product = document.getElementById('saleProduct')?.value?.trim();
  const amount = Number(document.getElementById('saleAmount')?.value || 0);
  const installmentsCount = Number(document.getElementById('saleInstallments')?.value || 0);
  const installmentAmount = Number(document.getElementById('saleInstallmentAmount')?.value || 0);
  const dueDate = document.getElementById('saleDueDate')?.value;
  const contractTextarea = document.getElementById('saleContract');
  
  if (!customerId || !product || !amount || !contractTextarea) return;
  
  // تحديث النص فقط إذا كانت الحقول مملوءة
  if (customerId && product && amount > 0) {
    const customer = getCustomers().find(c => c.id === customerId);
    const contractDate = dueDate ? new Date(dueDate) : new Date();
    const newContractText = generateContractText(customer, product, amount, 0, amount, installmentsCount, contractDate.toISOString(), installmentAmount);
    
    // تحديث النص فقط إذا كان المستخدم لم يعدل النص يدوياً بشكل كبير
    const currentText = contractTextarea.value;
    if (!currentText || 
        currentText.includes('[اسم المشتري]') || 
        currentText.includes('[اسم المنتج]') ||
        currentText.includes('[المبلغ]') ||
        currentText.includes('2 د.ع دينار عراقي') ||
        (currentText.includes('المبلغ الإجمالي:') && !currentText.includes(formatMoney(amount).split(' ')[0]))) {
      contractTextarea.value = newContractText;
    }
  }
}

// تم نقل كود تفاصيل الديون إلى initEventListeners()

// ========== البحث السريع ==========
let globalSearchTimeout = null;

function performGlobalSearch(query) {
  const queryLower = query.trim().toLowerCase();
  const customers = getCustomers();
  const sales = getSales();
  const results = {
    customers: customers.filter(c => 
      (c.name && c.name.toLowerCase().includes(query)) ||
      (c.phone && c.phone.includes(query)) ||
      (c.address && c.address.toLowerCase().includes(query))
    ),
    sales: sales.filter(s =>
      (s.customerName && s.customerName.toLowerCase().includes(query)) ||
      (s.product && s.product.toLowerCase().includes(query))
    )
  };
  
  if (results.customers.length === 0 && results.sales.length === 0) {
    toast('لا توجد نتائج', 'warning');
    return;
  }
  
  // عرض نتائج البحث في modal
  showSearchResults(results, query);
}

function showSearchResults(results, query) {
  const modal = document.createElement('div');
  modal.className = 'modal open';
  modal.innerHTML = `
    <div class="modal-content modal-wide">
      <div class="modal-header">
        <h3>نتائج البحث: "${query}"</h3>
        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
      </div>
      <div style="padding: 1.5rem; max-height: 70vh; overflow-y: auto;">
        ${results.customers.length > 0 ? `
          <h4 style="margin-bottom: 1rem; color: var(--text);">العملاء (${results.customers.length})</h4>
          <div class="cards-list">
            ${results.customers.map(c => `
              <div class="card">
                <div class="card-title">${escapeHtml(c.name)}</div>
                <div class="card-meta">${escapeHtml(c.phone)} ${c.address ? ' · ' + escapeHtml(c.address) : ''}</div>
                <div class="card-actions">
                  <button class="btn btn-secondary" onclick="showPage('customers'); openCustomerModal('${c.id}'); document.querySelector('.modal.open').remove();">عرض</button>
                </div>
              </div>
            `).join('')}
          </div>
        ` : ''}
        ${results.sales.length > 0 ? `
          <h4 style="margin: 1.5rem 0 1rem; color: var(--text);">المبيعات (${results.sales.length})</h4>
          <div class="cards-list">
            ${results.sales.map(s => {
              const remaining = s.totalAmount - (s.paidAmount || 0);
              return `
                <div class="card">
                  <div class="card-title">${escapeHtml(s.product)}</div>
                  <div class="card-meta">${escapeHtml(s.customerName)} · ${formatDate(s.date)}</div>
                  <div class="card-meta">الإجمالي: ${formatMoney(s.totalAmount)} · المتبقي: ${formatMoney(remaining)}</div>
                  <div class="card-actions">
                    <button class="btn btn-secondary" onclick="showPage('sales-list'); openSaleDetailModal('${s.id}'); document.querySelector('.modal.open').remove();">عرض</button>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        ` : ''}
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });
}

// تم نقل جميع event listeners إلى initEventListeners()

// ========== تصدير البيانات ==========
function exportData() {
  const customers = getCustomers();
  const sales = getSales();
  const activity = getActivity();
  const settings = getSettings();
  const externalDebts = getExternalDebts();
  const externalDebtTypes = getExternalDebtTypes();
  const data = {
    customers,
    sales,
    activity,
    settings,
    externalDebts,
    externalDebtTypes,
    exportDate: new Date().toISOString(),
    version: '1.0'
  };
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `اقساط_نسخة_احتياطية_${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('تم تصدير البيانات بنجاح');
}

// ========== استيراد البيانات ==========
function importData() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result);
        if (confirm('هل أنت متأكد من استيراد البيانات؟\nسيتم استبدال جميع البيانات الحالية.')) {
          if (data.customers) setCustomers(data.customers);
          if (data.sales) setSales(data.sales);
          if (data.activity) setActivity(data.activity);
          if (data.settings) setSettings(data.settings);
          if (data.externalDebts) setExternalDebts(data.externalDebts);
          if (data.externalDebtTypes) setExternalDebtTypes(data.externalDebtTypes);
          toast('تم استيراد البيانات بنجاح', 'success');
          fillSaleCustomerSelect();
          renderDashboard();
          const categoryFilter = document.querySelector('[data-customer-filter].active')?.dataset.customerFilter || 'all';
          renderCustomers(document.getElementById('customerSearch')?.value || '', categoryFilter);
          renderSalesList('', 'all');
          renderExternalDebts();
          renderActivity();
          renderLateList();
          updateLateBadge();
          renderSettings();
        }
      } catch (error) {
        toast('خطأ في استيراد البيانات. تأكد من صحة الملف.', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

// ========== طباعة العقد ==========
let currentSaleForPrint = null;
function printContract() {
  if (!currentSaleForPrint) return;
  const sale = currentSaleForPrint;
  const customer = getCustomers().find(c => c.id === sale.customerId);
  const remaining = sale.totalAmount - (sale.paidAmount || 0);
  
  const printWindow = window.open('', '_blank');
  printWindow.document.write(`
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
      <meta charset="UTF-8">
      <title>عقد البيع - ${escapeHtml(sale.product)}</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: 'Tajawal', Arial, sans-serif;
          padding: 2rem;
          line-height: 1.8;
          color: #1e293b;
        }
        .contract-header {
          text-align: center;
          margin-bottom: 2rem;
          padding-bottom: 1rem;
          border-bottom: 3px solid #0d9488;
        }
        .contract-header h1 {
          font-size: 1.8rem;
          color: #0d9488;
          margin-bottom: 0.5rem;
        }
        .contract-info {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1rem;
          margin-bottom: 2rem;
          padding: 1rem;
          background: #f8fafc;
          border-radius: 8px;
        }
        .contract-info-item {
          margin-bottom: 0.5rem;
        }
        .contract-info-label {
          font-weight: 700;
          color: #64748b;
          margin-left: 0.5rem;
        }
        .contract-text {
          background: #f0fdfa;
          padding: 1.5rem;
          border: 2px solid #0d9488;
          border-radius: 8px;
          margin: 2rem 0;
          white-space: pre-wrap;
          line-height: 2;
        }
        .contract-signatures {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 3rem;
          margin-top: 3rem;
          padding-top: 2rem;
          border-top: 2px solid #e2e8f0;
        }
        .signature-box {
          text-align: center;
        }
        .signature-line {
          border-top: 1px solid #1e293b;
          margin-top: 3rem;
          padding-top: 0.5rem;
        }
        @media print {
          body { padding: 1rem; }
          .no-print { display: none; }
        }
      </style>
    </head>
    <body>
      <div class="contract-header">
        <h1>عقد بيع</h1>
        <p>رقم العقد: <strong style="font-family: monospace; color: #0d9488;">${escapeHtml(sale.id)}</strong></p>
        <p>تاريخ: ${formatDate(sale.date)}</p>
      </div>
      <div class="contract-info">
        <div class="contract-info-item">
          <span class="contract-info-label">رقم البيع:</span>
          <strong style="font-family: monospace; color: #0d9488;">${escapeHtml(sale.id)}</strong>
        </div>
        <div class="contract-info-item">
          <span class="contract-info-label">العميل:</span>
          ${escapeHtml(sale.customerName)}
        </div>
        <div class="contract-info-item">
          <span class="contract-info-label">الهاتف:</span>
          ${customer ? escapeHtml(customer.phone || '—') : '—'}
        </div>
        <div class="contract-info-item">
          <span class="contract-info-label">المنتج:</span>
          ${escapeHtml(sale.product)}
        </div>
        <div class="contract-info-item">
          <span class="contract-info-label">المبلغ الإجمالي:</span>
          ${formatMoney(sale.totalAmount)}
        </div>
        <div class="contract-info-item">
          <span class="contract-info-label">المدفوع:</span>
          ${formatMoney(sale.paidAmount || 0)}
        </div>
        <div class="contract-info-item">
          <span class="contract-info-label">المتبقي:</span>
          ${formatMoney(remaining)}
        </div>
      </div>
      <div class="contract-text">${escapeHtml(sale.contractText || '—')}</div>
      ${(sale.payments && sale.payments.length) ? `
      <div style="margin-top: 2rem;">
        <h3 style="margin-bottom: 1rem;">سجل الأقساط:</h3>
        <ul style="padding-right: 1.5rem;">
          ${sale.payments.map(p => `<li>${formatMoney(p.amount)} - ${escapeHtml(p.note || 'قسط')} (${formatDate(p.date)})</li>`).join('')}
        </ul>
      </div>
      ` : ''}
      <div class="contract-signatures">
        <div class="signature-box">
          <p><strong>البائع</strong></p>
          <div class="signature-line"></div>
        </div>
        <div class="signature-box">
          <p><strong>المشتري</strong></p>
          <div class="signature-line"></div>
        </div>
      </div>
    </body>
    </html>
  `);
  printWindow.document.close();
  setTimeout(() => printWindow.print(), 250);
}

// ========== تعديل المبيعات ==========
function openEditSaleModal(saleId) {
  const sale = getSales().find(s => s.id === saleId);
  if (!sale) return;
  document.getElementById('editSaleId').value = saleId;
  document.getElementById('editSaleProduct').value = sale.product || '';
  document.getElementById('editSaleAmount').value = sale.totalAmount || '';
  document.getElementById('editSaleContract').value = sale.contractText || '';
  document.getElementById('editSaleModal').classList.add('open');
}

function saveEditSale(e) {
  e.preventDefault();
  const saleId = document.getElementById('editSaleId').value;
  const product = document.getElementById('editSaleProduct').value.trim();
  const amount = Number(document.getElementById('editSaleAmount').value);
  const contractText = document.getElementById('editSaleContract').value.trim();
  if (!saleId || !product || !amount || amount < 1) {
    toast('يرجى تعبئة جميع الحقول', 'error');
    return;
  }
  const sales = getSales();
  const sale = sales.find(s => s.id === saleId);
  if (!sale) {
    toast('البيع غير موجود', 'error');
    return;
  }
  sale.product = product;
  sale.totalAmount = amount;
  sale.contractText = contractText;
  setSales(sales);
  addActivity('sale', `تم تعديل البيع: ${product}`, { saleId });
  toast('تم تحديث البيع بنجاح');
  document.getElementById('editSaleModal').classList.remove('open');
  const filter = document.querySelector('.filter-tab.active')?.dataset.filter || 'all';
  renderSalesList(document.getElementById('salesSearch')?.value || '', filter);
  renderDashboard();
}

// ========== التقارير ==========
let currentReportPeriod = 'month';
function renderReports(period = 'month') {
  renderCharts(period);
  currentReportPeriod = period;
  const sales = getSales();
  const customers = getCustomers();
  const now = new Date();
  const currentMonth = now.getMonth();
  const currentYear = now.getFullYear();
  
  // فلترة حسب الفترة
  let filteredSales = sales;
  let periodTitle = 'تقرير هذا الشهر';
  if (period === 'year') {
    filteredSales = sales.filter(s => {
      const saleDate = new Date(s.date);
      return saleDate.getFullYear() === currentYear;
    });
    periodTitle = 'تقرير هذا العام';
  } else if (period === 'month') {
    filteredSales = sales.filter(s => {
      const saleDate = new Date(s.date);
      return saleDate.getMonth() === currentMonth && saleDate.getFullYear() === currentYear;
    });
    periodTitle = 'تقرير هذا الشهر';
  } else {
    periodTitle = 'تقرير شامل';
  }
  
  document.getElementById('reportPeriodTitle').textContent = periodTitle;
  
  let periodTotal = 0, periodPaid = 0, periodRemaining = 0;
  filteredSales.forEach(s => {
    periodTotal += s.totalAmount || 0;
    periodPaid += s.paidAmount || 0;
    periodRemaining += (s.totalAmount || 0) - (s.paidAmount || 0);
  });
  
  document.getElementById('monthlyReport').innerHTML = `
    <div class="report-stat">
      <span class="report-stat__label">عدد المبيعات</span>
      <span class="report-stat__value">${filteredSales.length}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">الإجمالي</span>
      <span class="report-stat__value">${formatMoney(periodTotal)}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">المدفوع</span>
      <span class="report-stat__value">${formatMoney(periodPaid)}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">المتبقي</span>
      <span class="report-stat__value">${formatMoney(periodRemaining)}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">نسبة التحصيل</span>
      <span class="report-stat__value">${periodTotal > 0 ? Math.round((periodPaid / periodTotal) * 100) : 0}%</span>
    </div>
  `;
  
  // أفضل العملاء (حسب عدد المبيعات)
  const customerSales = {};
  filteredSales.forEach(s => {
    if (!customerSales[s.customerId]) {
      customerSales[s.customerId] = { count: 0, total: 0, name: s.customerName };
    }
    customerSales[s.customerId].count++;
    customerSales[s.customerId].total += s.totalAmount || 0;
  });
  const topCustomers = Object.values(customerSales)
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);
  document.getElementById('topCustomersReport').innerHTML = topCustomers.length > 0
    ? topCustomers.map((c, i) => `
        <div class="report-item">
          <span class="report-item__rank">${i + 1}</span>
          <span class="report-item__name">${escapeHtml(c.name)}</span>
          <span class="report-item__value">${formatMoney(c.total)}</span>
        </div>
      `).join('')
    : '<p style="color: var(--text-muted); text-align: center; padding: 1rem;">لا توجد بيانات</p>';
  
  // ملخص المدفوعات
  let totalPayments = 0;
  filteredSales.forEach(s => {
    if (s.payments) totalPayments += s.payments.length;
  });
  const periodPayments = filteredSales.reduce((sum, s) => sum + (s.payments?.length || 0), 0);
  document.getElementById('paymentsReport').innerHTML = `
    <div class="report-stat">
      <span class="report-stat__label">إجمالي الأقساط</span>
      <span class="report-stat__value">${totalPayments}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">أقساط الفترة</span>
      <span class="report-stat__value">${periodPayments}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">متوسط القسط</span>
      <span class="report-stat__value">${periodPayments > 0 ? formatMoney(Math.round(periodPaid / periodPayments)) : formatMoney(0)}</span>
    </div>
  `;
  
  // إحصائيات المبيعات
  const completedSales = filteredSales.filter(s => {
    const rem = s.totalAmount - (s.paidAmount || 0);
    return rem <= 0;
  }).length;
  const activeSales = filteredSales.length - completedSales;
  const avgSaleAmount = filteredSales.length > 0 ? Math.round(periodTotal / filteredSales.length) : 0;
  document.getElementById('salesStatsReport').innerHTML = `
    <div class="report-stat">
      <span class="report-stat__label">مبيعات مكتملة</span>
      <span class="report-stat__value">${completedSales}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">مبيعات نشطة</span>
      <span class="report-stat__value">${activeSales}</span>
    </div>
    <div class="report-stat">
      <span class="report-stat__label">متوسط قيمة البيع</span>
      <span class="report-stat__value">${formatMoney(avgSaleAmount)}</span>
    </div>
  `;
}

// ========== الإعدادات ==========
function renderSettings() {
  try {
    const settings = getSettings();

    const setValue = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.value = value;
    };
    const setChecked = (id, checked) => {
      const el = document.getElementById(id);
      if (el) el.checked = !!checked;
    };

    setValue('lateDays', settings.lateDays || 30);
    setChecked('notifyOnLate', settings.notifyOnLate !== false);
    setChecked('darkMode', settings.darkMode === true);
    setChecked('autoSave', settings.autoSave === true);
    setChecked('showNotifications', settings.showNotifications !== false);
    setChecked('browserNotifications', settings.browserNotifications === true);
    setChecked('autoBackup', settings.autoBackup === true);
    setValue('itemsPerPage', settings.itemsPerPage || 20);
    setValue('dateFormat', settings.dateFormat || 'en-GB');
    setValue('fontSize', settings.fontSize || 'medium');
    setChecked('compactMode', settings.compactMode === true);
    setValue('notificationInterval', settings.notificationInterval || 5);
    setValue('backupRetention', settings.backupRetention || 7);
    setChecked('enableAnimations', settings.enableAnimations !== false);
    setChecked('showTooltips', settings.showTooltips === true);
  
  // تطبيق الإعدادات
  document.documentElement.setAttribute('data-font-size', settings.fontSize || 'medium');
  if (settings.compactMode) {
    document.body.classList.add('compact-mode');
  }
  if (settings.enableAnimations === false) {
    document.body.classList.add('no-animations');
  }
  
  if (settings.darkMode) {
    document.body.classList.add('dark-mode');
  }
  
    // طلب إذن الإشعارات إذا كان مفعلاً
    if (settings.browserNotifications && notificationPermission === 'default') {
      requestBrowserNotificationPermission();
    }

    // تحديث معلومات البيانات
    updateDataInfo();
    updateBrowserInfo();
  } catch (e) {
    console.error('Error rendering settings:', e);
  }
}

function updateDataInfo() {
  try {
    const customers = getCustomers();
    const sales = getSales();
    const activity = getActivity();
    
    let totalSize = 0;
    [customers, sales, activity].forEach(data => {
      totalSize += new Blob([JSON.stringify(data)]).size;
    });
    
    document.getElementById('dataSize').textContent = formatBytes(totalSize);
    document.getElementById('settingsCustomersCount').textContent = customers.length;
    document.getElementById('settingsSalesCount').textContent = sales.length;
    document.getElementById('settingsActivityCount').textContent = activity.length;
  } catch (e) {
    console.error('Error updating data info:', e);
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function updateBrowserInfo() {
  const ua = navigator.userAgent;
  let browser = 'غير معروف';
  if (ua.includes('Chrome')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari')) browser = 'Safari';
  else if (ua.includes('Edge')) browser = 'Edge';
  
  document.getElementById('browserInfo').textContent = browser;
  document.getElementById('storageSupport').textContent = typeof(Storage) !== 'undefined' ? 'مدعوم ✓' : 'غير مدعوم ✗';
}

function saveSettings(e) {
  e.preventDefault();
  const lateDays = Number(document.getElementById('lateDays').value);
  const notifyOnLate = document.getElementById('notifyOnLate').checked;
  const darkMode = document.getElementById('darkMode').checked;
  const autoSave = document.getElementById('autoSave').checked;
  const showNotifications = document.getElementById('showNotifications').checked;
  const browserNotifications = document.getElementById('browserNotifications').checked;
  const autoBackup = document.getElementById('autoBackup').checked;
  
  const settings = getSettings();
  setSettings({ 
    ...settings,
    lateDays, 
    notifyOnLate, 
    darkMode,
    autoSave,
    showNotifications,
    browserNotifications,
    autoBackup
  });
  
  if (browserNotifications && notificationPermission === 'default') {
    requestBrowserNotificationPermission();
  }
  
  if (darkMode) {
    document.body.classList.add('dark-mode');
  } else {
    document.body.classList.remove('dark-mode');
  }
  
  toast('تم حفظ الإعدادات بنجاح');
  renderDashboard();
  renderLateList();
  updateLateBadge();
  updateDataInfo();
}

function saveDisplaySettings() {
  const itemsPerPage = Number(document.getElementById('itemsPerPage').value);
  const dateFormat = document.getElementById('dateFormat').value;
  const fontSize = document.getElementById('fontSize').value;
  const compactMode = document.getElementById('compactMode').checked;
  
  const settings = getSettings();
  setSettings({ 
    ...settings,
    itemsPerPage,
    dateFormat,
    fontSize,
    compactMode
  });
  
  // تطبيق حجم الخط
  document.documentElement.setAttribute('data-font-size', fontSize);
  if (compactMode) {
    document.body.classList.add('compact-mode');
  } else {
    document.body.classList.remove('compact-mode');
  }
  
  toast('تم حفظ إعدادات العرض بنجاح');
  updateDataInfo();
}

function saveAdvancedSettings() {
  const notificationInterval = Number(document.getElementById('notificationInterval').value) || 5;
  const backupRetention = Number(document.getElementById('backupRetention').value) || 7;
  const enableAnimations = document.getElementById('enableAnimations').checked;
  const showTooltips = document.getElementById('showTooltips').checked;
  
  const settings = getSettings();
  setSettings({ 
    ...settings,
    notificationInterval,
    backupRetention,
    enableAnimations,
    showTooltips
  });
  
  // تطبيق الإعدادات
  if (!enableAnimations) {
    document.body.classList.add('no-animations');
  } else {
    document.body.classList.remove('no-animations');
  }
  
  toast('تم حفظ الإعدادات المتقدمة بنجاح');
}

function viewBackups() {
  try {
    const backups = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith('installments_backup_')) {
        const backupData = JSON.parse(localStorage.getItem(key));
        backups.push({
          key,
          date: backupData.timestamp || key,
          size: new Blob([JSON.stringify(backupData)]).size
        });
      }
    }
    
    if (backups.length === 0) {
      toast('لا توجد نسخ احتياطية', 'warning');
      return;
    }
    
    const backupList = backups.map(b => 
      `📋 ${new Date(b.date).toLocaleString('ar-IQ')} - ${formatBytes(b.size)}`
    ).join('\n');
    
    const selected = prompt(`النسخ الاحتياطية المتاحة:\n\n${backupList}\n\nأدخل رقم النسخة للاستعادة (1-${backups.length}):`);
    const index = parseInt(selected) - 1;
    
    if (index >= 0 && index < backups.length) {
      if (confirm('هل تريد استعادة هذه النسخة؟ سيتم استبدال البيانات الحالية.')) {
        const backupKey = backups[index].key;
        const backupData = JSON.parse(localStorage.getItem(backupKey));
        
        if (backupData.customers) setCustomers(backupData.customers);
        if (backupData.sales) setSales(backupData.sales);
        if (backupData.activity) setActivity(backupData.activity);
        if (backupData.settings) setSettings(backupData.settings);
        
        toast('تم استعادة النسخة الاحتياطية بنجاح');
        location.reload();
      }
    }
  } catch (e) {
    toast('خطأ في عرض النسخ الاحتياطية', 'error');
    console.error(e);
  }
}

function createManualBackup() {
  try {
    const backupData = {
      customers: getCustomers(),
      sales: getSales(),
      activity: getActivity(),
      settings: getSettings(),
      timestamp: new Date().toISOString(),
      type: 'manual'
    };
    
    const backupKey = 'installments_backup_' + Date.now();
    localStorage.setItem(backupKey, JSON.stringify(backupData));
    
    toast('تم إنشاء نسخة احتياطية يدوية بنجاح');
  } catch (e) {
    toast('خطأ في إنشاء النسخة الاحتياطية', 'error');
    console.error(e);
  }
}

// ========== تصدير CSV ==========
function exportToCSV() {
  const customers = getCustomers();
  const sales = getSales();
  
  // تصدير العملاء
  let csv = 'العملاء\n';
  csv += 'الاسم,الهاتف,العنوان\n';
  customers.forEach(c => {
    csv += `"${c.name || ''}","${c.phone || ''}","${c.address || ''}"\n`;
  });
  
  csv += '\n\nالمبيعات\n';
  csv += 'المنتج,العميل,المبلغ الإجمالي,المدفوع,المتبقي,التاريخ\n';
  sales.forEach(s => {
    const remaining = s.totalAmount - (s.paidAmount || 0);
    csv += `"${s.product || ''}","${s.customerName || ''}",${s.totalAmount || 0},${s.paidAmount || 0},${remaining},"${formatDate(s.date)}"\n`;
  });
  
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `اقساط_تصدير_${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  toast('تم تصدير البيانات بصيغة CSV بنجاح');
}

function clearAllData() {
  if (confirm('هل أنت متأكد من حذف جميع البيانات؟\nهذه العملية لا يمكن التراجع عنها!')) {
    if (confirm('تأكيد نهائي: سيتم حذف جميع العملاء والمبيعات والحركات. هل أنت متأكد؟')) {
      localStorage.removeItem(STORAGE_KEYS.customers);
      localStorage.removeItem(STORAGE_KEYS.sales);
      localStorage.removeItem(STORAGE_KEYS.activity);
      toast('تم حذف جميع البيانات', 'warning');
      fillSaleCustomerSelect();
      renderDashboard();
      renderCustomers();
      renderSalesList('', 'all');
      renderActivity();
      renderLateList();
      updateLateBadge();
      updateDataInfo();
    }
  }
}

// ========== التشغيل الأولي ==========
function __authOkOrRedirect() {
  try {
    if (window.auth) {
      window.auth.ensureDefaultUser();
      if (!window.auth.isLoggedIn()) {
        window.auth.redirectToLogin('index.html');
        return false;
      }
    }
  } catch (_) {
    // إذا صار خطأ في auth، نخلي التطبيق يشتغل مثل السابق
  }
  return true;
}

const __AUTH_OK__ = __authOkOrRedirect();

if (__AUTH_OK__) {
  // تطبيق Dark Mode إذا كان مفعلاً
  const settings = getSettings();
  if (settings.darkMode) {
    document.body.classList.add('dark-mode');
  }

  fillSaleCustomerSelect();
  renderDashboard();
  renderCustomers();
  renderSalesList('', 'all');
  renderActivity();
  renderLateList();
  updateLateBadge();

  // إشعار المتأخرين عند فتح الصفحة
  (function checkLateOnLoad() {
    const settings = getSettings();
    if (settings.notifyOnLate !== false) {
      const late = getLateSales();
      if (late.length > 0) {
        const totalDebt = late.reduce((sum, s) => sum + (s.totalAmount - (s.paidAmount || 0)), 0);
        toast(`تنبيه: يوجد ${late.length} عميل متأخر عن السداد (${formatMoney(totalDebt)}). راجع صفحة "المتأخرون عن السداد".`, 'warning');
      }
    }
  })();

  // تذكير دوري للمتأخرين (كل 5 دقائق)
  setInterval(() => {
    const settings = getSettings();
    if (settings.showNotifications && settings.notifyOnLate !== false) {
      const late = getLateSales();
      if (late.length > 0) {
        const totalDebt = late.reduce((sum, s) => sum + (s.totalAmount - (s.paidAmount || 0)), 0);
        if (document.getElementById('page-dashboard')?.classList.contains('active')) {
          toast(`تذكير: ${late.length} عميل متأخر (${formatMoney(totalDebt)})`, 'warning');
        }
        // إشعار المتصفح
        showBrowserNotification(
          'تذكير: عملاء متأخرون',
          `${late.length} عميل متأخر عن السداد (${formatMoney(totalDebt)})`
        );
      }
    }
    
    // التحقق من الأقساط القادمة
    const sales = getSales();
    const now = new Date();
    sales.forEach(sale => {
      if (sale.installmentsSchedule && sale.installmentsSchedule.length > 0) {
        sale.installmentsSchedule.forEach(installment => {
          if (!installment.paid) {
            const dueDate = new Date(installment.dueDate);
            const hoursUntil = (dueDate - now) / (1000 * 60 * 60);
            // إشعار قبل 24 ساعة من موعد القسط
            if (hoursUntil > 0 && hoursUntil <= 24 && hoursUntil >= 23.5) {
              showBrowserNotification(
                'قسط قادم غداً',
                `${sale.customerName}: ${formatMoney(installment.amount)} - ${sale.product}`
              );
            }
          }
        });
      }
    });
  }, 5 * 60 * 1000); // كل 5 دقائق
}

// ========== الأقساط القادمة ==========
function renderUpcomingInstallments() {
  const container = document.getElementById('upcomingList');
  if (!container) return;
  
  const sales = getSales();
  const upcoming = [];
  const now = new Date();
  const sevenDaysLater = new Date(now);
  sevenDaysLater.setDate(now.getDate() + 7);
  
  sales.forEach(sale => {
    if (sale.installmentsSchedule && sale.installmentsSchedule.length > 0) {
      sale.installmentsSchedule.forEach(installment => {
        if (!installment.paid) {
          const dueDate = new Date(installment.dueDate);
          if (dueDate >= now && dueDate <= sevenDaysLater) {
            upcoming.push({
              sale,
              installment,
              dueDate
            });
          }
        }
      });
    } else if (sale.dueDate) {
      const dueDate = new Date(sale.dueDate);
      const remaining = sale.totalAmount - (sale.paidAmount || 0);
      if (remaining > 0 && dueDate >= now && dueDate <= sevenDaysLater) {
        upcoming.push({
          sale,
          installment: { number: 1, amount: remaining },
          dueDate
        });
      }
    }
  });
  
  upcoming.sort((a, b) => a.dueDate - b.dueDate);
  
  if (upcoming.length === 0) {
    container.innerHTML = '<div class="empty-state visible">لا توجد أقساط قادمة خلال 7 أيام</div>';
    return;
  }
  
  container.innerHTML = upcoming.map(item => {
    const daysUntil = Math.ceil((item.dueDate - now) / (1000 * 60 * 60 * 24));
    const isToday = daysUntil === 0;
    const isTomorrow = daysUntil === 1;
    
    return `
      <div class="upcoming-item ${isToday ? 'upcoming-item--today' : ''}">
        <div class="upcoming-item__header">
          <span class="upcoming-item__customer">${escapeHtml(item.sale.customerName)}</span>
          <span class="upcoming-item__days ${isToday ? 'upcoming-item__days--urgent' : ''}">
            ${isToday ? 'اليوم' : isTomorrow ? 'غداً' : `بعد ${daysUntil} أيام`}
          </span>
        </div>
        <div class="upcoming-item__details">
          <span>${escapeHtml(item.sale.product)}</span>
          <strong>${formatMoney(item.installment.amount)}</strong>
        </div>
        <div class="upcoming-item__date">${formatDate(item.dueDate)}</div>
      </div>
    `;
  }).join('');
}

// ========== الرسوم البيانية ==========
function renderCharts(period = 'month') {
  const sales = getSales();
  const now = new Date();
  const currentMonth = now.getMonth();
  const currentYear = now.getFullYear();
  
  // فلترة حسب الفترة
  let filteredSales = sales;
  if (period === 'year') {
    filteredSales = sales.filter(s => {
      const saleDate = new Date(s.date);
      return saleDate.getFullYear() === currentYear;
    });
  } else if (period === 'month') {
    filteredSales = sales.filter(s => {
      const saleDate = new Date(s.date);
      return saleDate.getMonth() === currentMonth && saleDate.getFullYear() === currentYear;
    });
  }
  
  // رسم بياني للمبيعات الشهرية (آخر 6 أشهر)
  const salesChart = document.getElementById('salesChart');
  if (salesChart) {
    const ctx = salesChart.getContext('2d');
    const months = [];
    const salesData = [];
    const paymentsData = [];
    
    for (let i = 5; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthName = date.toLocaleDateString('ar-SA', { month: 'short' });
      months.push(monthName);
      
      const monthSales = sales.filter(s => {
        const saleDate = new Date(s.date);
        return saleDate.getMonth() === date.getMonth() && saleDate.getFullYear() === date.getFullYear();
      });
      
      const monthTotal = monthSales.reduce((sum, s) => sum + (s.totalAmount || 0), 0);
      const monthPaid = monthSales.reduce((sum, s) => sum + (s.paidAmount || 0), 0);
      
      salesData.push(monthTotal);
      paymentsData.push(monthPaid);
    }
    
    drawBarChart(ctx, months, salesData, paymentsData, 'المبيعات', 'المدفوعات');
  }
  
  // رسم بياني دائري للمدفوعات
  const paymentsChart = document.getElementById('paymentsChart');
  if (paymentsChart) {
    const ctx = paymentsChart.getContext('2d');
    let totalPaid = 0;
    let totalRemaining = 0;
    
    filteredSales.forEach(s => {
      totalPaid += s.paidAmount || 0;
      totalRemaining += (s.totalAmount || 0) - (s.paidAmount || 0);
    });
    
    drawPieChart(ctx, totalPaid, totalRemaining);
  }
}

function drawBarChart(ctx, labels, data1, data2, label1, label2) {
  const width = ctx.canvas.width;
  const height = ctx.canvas.height;
  const padding = 40;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;
  const barWidth = chartWidth / labels.length / 3;
  const maxValue = Math.max(...data1, ...data2, 1);
  
  ctx.clearRect(0, 0, width, height);
  
  // رسم المحاور
  ctx.strokeStyle = '#e2e8f0';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding, padding);
  ctx.lineTo(padding, height - padding);
  ctx.lineTo(width - padding, height - padding);
  ctx.stroke();
  
  // رسم الأعمدة
  labels.forEach((label, i) => {
    const x = padding + (i * chartWidth / labels.length) + barWidth;
    const bar1Height = (data1[i] / maxValue) * chartHeight;
    const bar2Height = (data2[i] / maxValue) * chartHeight;
    
    // عمود المبيعات
    ctx.fillStyle = '#0d9488';
    ctx.fillRect(x, height - padding - bar1Height, barWidth, bar1Height);
    
    // عمود المدفوعات
    ctx.fillStyle = '#059669';
    ctx.fillRect(x + barWidth, height - padding - bar2Height, barWidth, bar2Height);
    
    // التسميات
    ctx.fillStyle = '#64748b';
    ctx.font = '10px Tajawal';
    ctx.textAlign = 'center';
    ctx.fillText(label, x + barWidth, height - padding + 15);
  });
  
  // المفتاح
  ctx.fillStyle = '#0d9488';
  ctx.fillRect(width - 100, 10, 15, 15);
  ctx.fillStyle = '#1e293b';
  ctx.font = '11px Tajawal';
  ctx.textAlign = 'right';
  ctx.fillText(label1, width - 80, 22);
  
  ctx.fillStyle = '#059669';
  ctx.fillRect(width - 100, 30, 15, 15);
  ctx.fillStyle = '#1e293b';
  ctx.fillText(label2, width - 80, 42);
}

function drawPieChart(ctx, paid, remaining) {
  const width = ctx.canvas.width;
  const height = ctx.canvas.height;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) / 2 - 20;
  const total = paid + remaining;
  
  ctx.clearRect(0, 0, width, height);
  
  if (total === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '14px Tajawal';
    ctx.textAlign = 'center';
    ctx.fillText('لا توجد بيانات', centerX, centerY);
    return;
  }
  
  const paidAngle = (paid / total) * 2 * Math.PI;
  const remainingAngle = (remaining / total) * 2 * Math.PI;
  
  // رسم القطاع المدفوع
  ctx.beginPath();
  ctx.moveTo(centerX, centerY);
  ctx.arc(centerX, centerY, radius, 0, paidAngle);
  ctx.closePath();
  ctx.fillStyle = '#059669';
  ctx.fill();
  
  // رسم القطاع المتبقي
  ctx.beginPath();
  ctx.moveTo(centerX, centerY);
  ctx.arc(centerX, centerY, radius, paidAngle, paidAngle + remainingAngle);
  ctx.closePath();
  ctx.fillStyle = '#f59e0b';
  ctx.fill();
  
  // النص
  ctx.fillStyle = '#1e293b';
  ctx.font = 'bold 12px Tajawal';
  ctx.textAlign = 'center';
  const paidPercent = Math.round((paid / total) * 100);
  ctx.fillText(`${paidPercent}%`, centerX, centerY - 5);
  ctx.font = '10px Tajawal';
  ctx.fillText('مدفوع', centerX, centerY + 10);
}

// ========== إشعارات المتصفح ==========
// notificationPermission تم تعريفه في أعلى الملف

function requestBrowserNotificationPermission() {
  if (!('Notification' in window)) {
    toast('المتصفح لا يدعم الإشعارات', 'warning');
    return;
  }
  
  if (Notification.permission === 'default') {
    Notification.requestPermission().then(permission => {
      notificationPermission = permission;
      if (permission === 'granted') {
        toast('تم تفعيل إشعارات المتصفح');
      }
    });
  }
}

function showBrowserNotification(title, body, icon = '📒') {
  const settings = getSettings();
  if (!settings.browserNotifications || notificationPermission !== 'granted') return;
  
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification(title, {
      body,
      icon: '/favicon.ico',
      badge: icon,
      tag: 'installment-notification',
      requireInteraction: false
    });
  }
}

// ========== النسخ الاحتياطي التلقائي ==========
function performAutoBackup() {
  const settings = getSettings();
  if (!settings.autoBackup) return;
  
  try {
    const backupData = {
      customers: getCustomers(),
      sales: getSales(),
      activity: getActivity(),
      settings: getSettings(),
      timestamp: new Date().toISOString()
    };
    
    const backupKey = 'installments_auto_backup_' + new Date().toISOString().split('T')[0];
    localStorage.setItem(backupKey, JSON.stringify(backupData));
    
    // الاحتفاظ بآخر 7 نسخ احتياطية فقط
    const backupKeys = Object.keys(localStorage).filter(k => k.startsWith('installments_auto_backup_'));
    if (backupKeys.length > 7) {
      backupKeys.sort().slice(0, backupKeys.length - 7).forEach(k => {
        localStorage.removeItem(k);
      });
    }
  } catch (e) {
    console.error('Error performing auto backup:', e);
  }
}

if (__AUTH_OK__) {
  // تشغيل النسخ الاحتياطي التلقائي كل يوم
  setInterval(() => {
    performAutoBackup();
  }, 24 * 60 * 60 * 1000); // كل 24 ساعة

  // تهيئة التطبيق عند تحميل الصفحة
  initApp();

  // تشغيل النسخ الاحتياطي عند تحميل الصفحة
  performAutoBackup();
  syncInstallmentsWithPayments();
}
