const { createApp, ref, computed, onMounted } = Vue;

createApp({
    setup() {
        // Core application state
        const loading = ref(true);
        const error = ref(null);
        const backendData = ref(null);
        
        const currentPage = ref('dashboard');
        const selectedOrgId = ref('ORG-001');
        const mobileLayoutOpen = ref(false);
        const theme = ref('dark');

        // ==========================================
        // AUTHENTICATION STATE & LOGIC
        // ==========================================
        const isAuthenticated = ref(false);
        const authLoading = ref(false);
        const authSuccess = ref(false);
        
        const authForm = ref({
            email: '',
            password: '',
            rememberMe: true,
            showPassword: false
        });

        const authErrors = ref({
            email: '',
            password: '',
            general: ''
        });

        const currentUser = ref({
            name: 'SecOps Analyst',
            email: 'analyst@vulntriage.sec',
            role: 'Lead Vulnerability Analyst',
            clearance: 'LEVEL 4 - SEC-NET'
        });

        // Modals for Forgot Password & Enterprise Account Provisioning
        const showForgotModal = ref(false);
        const forgotEmail = ref('');
        const forgotSubmitted = ref(false);

        const showSignupModal = ref(false);
        const signupForm = ref({
            name: '',
            email: '',
            organization: 'ORG-001 (Global Financial Services)',
            clearanceLevel: 'Level 2 - Standard Analyst',
            justification: ''
        });
        const signupSubmitted = ref(false);

        // Check for existing session token
        const checkSavedSession = () => {
            try {
                const saved = localStorage.getItem('vulntriage_session') || sessionStorage.getItem('vulntriage_session');
                if (saved) {
                    const parsed = JSON.parse(saved);
                    if (parsed && parsed.token && parsed.user) {
                        currentUser.value = parsed.user;
                        isAuthenticated.value = true;
                    }
                }
            } catch (e) {
                console.warn('Could not restore auth session:', e);
            }
        };

        // Form validation
        const validateEmailFormat = (email) => {
            const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return re.test(String(email).toLowerCase());
        };

        const validateLoginForm = () => {
            let valid = true;
            authErrors.value.email = '';
            authErrors.value.password = '';
            authErrors.value.general = '';

            const trimmedEmail = (authForm.value.email || '').trim();
            const trimmedPassword = (authForm.value.password || '').trim();

            if (!trimmedEmail) {
                authErrors.value.email = 'Please enter your work email.';
                valid = false;
            } else if (!validateEmailFormat(trimmedEmail)) {
                authErrors.value.email = 'Please enter a valid email address.';
                valid = false;
            }

            if (!trimmedPassword) {
                authErrors.value.password = 'Password is required.';
                valid = false;
            } else if (trimmedPassword.length < 6) {
                authErrors.value.password = 'Password must be at least 6 characters.';
                valid = false;
            }

            return valid;
        };

        const handleLogin = () => {
            if (!validateLoginForm()) return;

            authLoading.value = true;
            authErrors.value.general = '';

            setTimeout(() => {
                const emailLower = authForm.value.email.trim().toLowerCase();
                const defaultEmail = 'analyst@vulntriage.sec';
                const defaultPass = 'security2026';

                if ((emailLower === defaultEmail && authForm.value.password === defaultPass) ||
                    (validateEmailFormat(authForm.value.email) && authForm.value.password.length >= 6)) {
                    
                    authSuccess.value = true;
                    
                    let nameDisplay = 'SecOps Operator';
                    if (emailLower.includes('@')) {
                        const localPart = emailLower.split('@')[0];
                        nameDisplay = localPart.charAt(0).toUpperCase() + localPart.slice(1) + ' (SecOps)';
                    }
                    
                    currentUser.value = {
                        name: nameDisplay,
                        email: authForm.value.email.trim(),
                        role: 'Lead Triage Officer',
                        clearance: 'LEVEL 4 - AUTHORIZED'
                    };

                    const sessionPayload = {
                        token: 'vsec_' + Math.random().toString(36).substring(2) + Date.now(),
                        user: currentUser.value
                    };

                    try {
                        if (authForm.value.rememberMe) {
                            localStorage.setItem('vulntriage_session', JSON.stringify(sessionPayload));
                        } else {
                            sessionStorage.setItem('vulntriage_session', JSON.stringify(sessionPayload));
                        }
                    } catch (e) {
                        console.warn('Storage save failed:', e);
                    }

                    setTimeout(() => {
                        isAuthenticated.value = true;
                        authLoading.value = false;
                        authSuccess.value = false;
                        fetchData();
                        fetchAiStatus();
                    }, 400);
                } else {
                    authLoading.value = false;
                    authErrors.value.general = 'Invalid credentials. Check email and password.';
                }
            }, 600);
        };

        const handleLogout = () => {
            try {
                localStorage.removeItem('vulntriage_session');
                sessionStorage.removeItem('vulntriage_session');
            } catch (e) {}
            isAuthenticated.value = false;
            authForm.value.password = '';
            authErrors.value.general = '';
            currentPage.value = 'dashboard';
        };

        const fastFillDemo = () => {
            authForm.value.email = 'analyst@vulntriage.sec';
            authForm.value.password = 'security2026';
            authErrors.value.email = '';
            authErrors.value.password = '';
            authErrors.value.general = '';
        };

        const togglePasswordVisibility = () => {
            authForm.value.showPassword = !authForm.value.showPassword;
        };

        const openForgotModal = () => {
            forgotEmail.value = authForm.value.email || '';
            forgotSubmitted.value = false;
            showForgotModal.value = true;
        };

        const closeForgotModal = () => {
            showForgotModal.value = false;
            forgotSubmitted.value = false;
        };

        const submitForgot = () => {
            if (!forgotEmail.value || !validateEmailFormat(forgotEmail.value)) {
                return;
            }
            forgotSubmitted.value = true;
        };

        const openSignupModal = () => {
            signupSubmitted.value = false;
            signupForm.value = {
                name: '',
                email: authForm.value.email || '',
                organization: 'ORG-001 (Global Retail Bank)',
                clearanceLevel: 'Level 2 - Standard Analyst',
                justification: ''
            };
            showSignupModal.value = true;
        };

        const closeSignupModal = () => {
            showSignupModal.value = false;
            signupSubmitted.value = false;
        };

        const submitSignup = () => {
            if (!signupForm.value.name || !signupForm.value.email || !validateEmailFormat(signupForm.value.email)) {
                return;
            }
            signupSubmitted.value = true;
        };

        // ==========================================
        // SECURITY HARDENING STATUS MODAL
        // ==========================================
        const showSecurityModal = ref(false);

        // ==========================================
        // FEATHERLESS AI ADVISORY STATE & ACTIONS
        // ==========================================
        const showAiModal = ref(false);
        const aiLoading = ref(false);
        const aiError = ref(null);
        const aiAnalysisData = ref(null);
        const aiServiceStatus = ref({ configured: false, provider: "Featherless AI", status: "checking" });

        const fetchAiStatus = async () => {
            try {
                const res = await fetch('/api/ai/status');
                if (res.ok) {
                    aiServiceStatus.value = await res.json();
                }
            } catch (e) {
                console.warn('AI status check failed:', e);
            }
        };

        const openAiAnalysis = async (vuln) => {
            if (!vuln) return;
            showAiModal.value = true;
            aiLoading.value = true;
            aiError.value = null;
            aiAnalysisData.value = null;

            try {
                const res = await fetch('/api/ai/analyze-vulnerability', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        org_id: selectedOrgId.value,
                        cve_id: vuln.cve_id,
                        product_name: vuln.product_name
                    })
                });

                if (!res.ok) {
                    const errJson = await res.json().catch(() => ({}));
                    throw new Error(errJson.error || `HTTP Network Error: ${res.status}`);
                }

                const data = await res.json();
                aiAnalysisData.value = data;
            } catch (err) {
                console.error("AI Analysis error:", err);
                aiError.value = err.message || "Failed to retrieve AI analysis.";
            } finally {
                aiLoading.value = false;
            }
        };

        const closeAiModal = () => {
            showAiModal.value = false;
            aiAnalysisData.value = null;
            aiError.value = null;
        };

        // ==========================================
        // FEATURE 1: AUTO UPLOAD & SCHEMA DETECTION
        // ==========================================
        const fileInputRef = ref(null);
        const uploading = ref(false);
        const uploadError = ref(null);
        const uploadInspectData = ref(null);
        const rawUploadedContent = ref('');
        const rawUploadedFilename = ref('');
        const importSuccessSummary = ref(null);
        const isDragOver = ref(false);

        const triggerChooseFile = () => {
            if (fileInputRef.value) {
                fileInputRef.value.click();
            }
        };

        const inspectFileContent = async (contentStr, filename) => {
            uploading.value = true;
            uploadError.value = null;
            uploadInspectData.value = null;
            importSuccessSummary.value = null;
            rawUploadedContent.value = contentStr;
            rawUploadedFilename.value = filename;

            try {
                const res = await fetch('/api/upload/inspect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        file_content: contentStr,
                        filename: filename
                    })
                });

                const data = await res.json();
                if (!res.ok && !data.dataset_type) {
                    throw new Error(data.error || `Upload inspection failed with code ${res.status}`);
                }
                uploadInspectData.value = data;
            } catch (err) {
                uploadError.value = err.message || "Failed to inspect uploaded file.";
            } finally {
                uploading.value = false;
            }
        };

        const onFileSelected = (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            processUploadedFileObject(file);
        };

        const onFileDrop = (e) => {
            isDragOver.value = false;
            const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
            if (!file) return;
            processUploadedFileObject(file);
        };

        const processUploadedFileObject = (file) => {
            const allowedExts = ['.csv', '.json', '.txt'];
            const nameLower = file.name.toLowerCase();
            const validExt = allowedExts.some(ext => nameLower.endsWith(ext));

            if (!validExt) {
                uploadError.value = `Unsupported file format '${file.name}'. Supported extensions: CSV, JSON.`;
                return;
            }

            if (file.size > 25 * 1024 * 1024) {
                uploadError.value = `File size exceeds 25MB limit (${(file.size / 1024 / 1024).toFixed(1)}MB).`;
                return;
            }

            const reader = new FileReader();
            reader.onload = (event) => {
                const content = event.target.result;
                inspectFileContent(content, file.name);
            };
            reader.onerror = () => {
                uploadError.value = "Failed to read local file from device.";
            };
            reader.readAsText(file);
        };

        const importAndActivateDataset = async () => {
            if (!rawUploadedContent.value) {
                uploadError.value = "No inspected dataset available to import.";
                return;
            }

            uploading.value = true;
            uploadError.value = null;

            try {
                const res = await fetch('/api/upload/import', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        file_content: rawUploadedContent.value,
                        filename: rawUploadedFilename.value
                    })
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.error || `Import failed with code ${res.status}`);
                }

                const data = await res.json();
                backendData.value = data;
                importSuccessSummary.value = data.import_summary;
                
                // Clear simulation state on new dataset load
                resetSimulation();
                fetchBestFirstFix();
            } catch (err) {
                uploadError.value = err.message || "Failed to import dataset into engine.";
            } finally {
                uploading.value = false;
            }
        };

        const loadDemoDataset = async () => {
            await resetToBundledBaseline();
        };

        const resetToBundledBaseline = async () => {
            uploading.value = true;
            uploadError.value = null;
            uploadInspectData.value = null;
            importSuccessSummary.value = null;

            try {
                const res = await fetch('/api/dataset/reset', { method: 'POST' });
                if (!res.ok) {
                    throw new Error(`Reset failed with code ${res.status}`);
                }
                const data = await res.json();
                backendData.value = data;
                
                resetSimulation();
                fetchBestFirstFix();
            } catch (err) {
                uploadError.value = err.message || "Failed to reset to default dataset.";
            } finally {
                uploading.value = false;
            }
        };

        // ==========================================
        // FEATURE 2: WHAT-IF RISK SIMULATOR
        // ==========================================
        const simulating = ref(false);
        const simError = ref(null);
        const simulationResult = ref(null);
        const selectedRemediatedPairs = ref(new Set()); // Keys: "CVE_ID|PRODUCT_NAME"
        const bestFixLoading = ref(false);
        const bestFixResult = ref(null);
        const showSimModal = ref(false);
        const simModalTargetVuln = ref(null);

        const pairKey = (cve, prod) => `${(cve || '').trim().toUpperCase()}|${(prod || '').trim().toLowerCase()}`;

        const isPairRemediated = (cve, prod) => {
            return selectedRemediatedPairs.value.has(pairKey(cve, prod));
        };

        const toggleRemediationPair = (cve, prod) => {
            const k = pairKey(cve, prod);
            if (selectedRemediatedPairs.value.has(k)) {
                selectedRemediatedPairs.value.delete(k);
            } else {
                selectedRemediatedPairs.value.add(k);
            }
            runSimulation();
        };

        const openSimulationModal = (vuln) => {
            if (!vuln) return;
            simModalTargetVuln.value = vuln;
            showSimModal.value = true;
            
            // Auto-select this specific vuln for simulation
            selectedRemediatedPairs.value.clear();
            selectedRemediatedPairs.value.add(pairKey(vuln.cve_id, vuln.product_name));
            runSimulation();
        };

        const closeSimulationModal = () => {
            showSimModal.value = false;
            simModalTargetVuln.value = null;
        };

        const runSimulation = async () => {
            simulating.value = true;
            simError.value = null;

            const pairsArray = Array.from(selectedRemediatedPairs.value).map(k => {
                const parts = k.split('|');
                return { cve_id: parts[0], product_name: parts[1] };
            });

            try {
                const res = await fetch('/api/simulation/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        org_id: selectedOrgId.value,
                        remediated_pairs: pairsArray
                    })
                });

                if (!res.ok) {
                    const errJson = await res.json().catch(() => ({}));
                    throw new Error(errJson.error || `Simulation failed with code ${res.status}`);
                }

                const data = await res.json();
                simulationResult.value = data;
            } catch (err) {
                simError.value = err.message || "Failed to execute simulation.";
            } finally {
                simulating.value = false;
            }
        };

        const resetSimulation = () => {
            selectedRemediatedPairs.value.clear();
            simulationResult.value = null;
            simError.value = null;
            if (currentPage.value === 'simulator') {
                runSimulation();
            }
        };

        const fetchBestFirstFix = async () => {
            bestFixLoading.value = true;
            try {
                const res = await fetch('/api/simulation/best-fix', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ org_id: selectedOrgId.value })
                });
                if (res.ok) {
                    bestFixResult.value = await res.json();
                }
            } catch (e) {
                console.warn('Best fix fetch error:', e);
            } finally {
                bestFixLoading.value = false;
            }
        };

        const applyBestFixToSimulation = () => {
            if (!bestFixResult.value || !bestFixResult.value.recommended_cve) return;
            selectedRemediatedPairs.value.clear();
            selectedRemediatedPairs.value.add(
                pairKey(bestFixResult.value.recommended_cve, bestFixResult.value.recommended_product)
            );
            runSimulation();
        };

        // ==========================================
        // EXISTING DASHBOARD APPLICATION STATE
        // ==========================================
        const expandedVulnCves = ref(new Set());
        
        const searchQuery = ref('');
        const productFilter = ref('');
        const kevFilter = ref('');
        const sortOption = ref('risk_score');
        
        const showModal = ref(false);
        const selectedVulnDetail = ref(null);

        // Sidebar Navigation
        const navItems = [
            {
                id: 'dashboard',
                label: 'Dashboard',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>`
            },
            {
                id: 'upload',
                label: 'Upload & Analyze',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>`
            },
            {
                id: 'simulator',
                label: 'Risk Simulator',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>`
            },
            {
                id: 'organizations',
                label: 'Organizations',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`
            },
            {
                id: 'top_vulns',
                label: 'Top Vulnerabilities',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`
            },
            {
                id: 'all_findings',
                label: 'All Findings',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`
            },
            {
                id: 'validation',
                label: 'Validation',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`
            },
            {
                id: 'reports',
                label: 'Reports',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>`
            },
            {
                id: 'settings',
                label: 'Settings',
                icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`
            }
        ];

        // Fetch application state data from server API
        const fetchData = async () => {
            loading.value = true;
            error.value = null;
            try {
                const response = await fetch('/api/data');
                if (!response.ok) {
                    throw new Error(`HTTP network error code: ${response.status}`);
                }
                const data = await response.json();
                if (data.error) {
                    throw new Error(data.error);
                }
                backendData.value = data;
                
                // Initialize default expand states for top5
                const currentTop5 = data.org_data[selectedOrgId.value]?.top_5 || [];
                expandedVulnCves.value.clear();
                if (currentTop5.length > 0) {
                    expandedVulnCves.value.add(currentTop5[0].cve_id + '-' + currentTop5[0].product_name);
                }
                
                fetchBestFirstFix();
            } catch (err) {
                console.error("Data fetch error:", err);
                error.value = err.message || "Failed to establish uplink with VULNTRIAGE backend service.";
            } finally {
                loading.value = false;
            }
        };

        const currentOrg = computed(() => {
            if (!backendData.value || !backendData.value.organizations) return { name: '', sector: '', risk_appetite: '', critical_products: [], weight_modifiers: {} };
            return backendData.value.organizations.find(o => o.org_id === selectedOrgId.value) || backendData.value.organizations[0];
        });

        const currentOrgData = computed(() => {
            if (!backendData.value || !backendData.value.org_data) {
                return { matched_count: 0, match_report: { matched_count: 0, zero_match_products: [] }, top_5: [], ranked_vulnerabilities: [] };
            }
            const data = backendData.value.org_data[selectedOrgId.value];
            if (!data) {
                return { matched_count: 0, match_report: { matched_count: 0, zero_match_products: [] }, top_5: [], ranked_vulnerabilities: [] };
            }
            const count = (data.matched_count !== undefined && data.matched_count !== null) ? data.matched_count :
                          (data.match_report && data.match_report.matched_count !== undefined ? data.match_report.matched_count :
                          (data.match_report && data.match_report.matched_vulnerabilities ? data.match_report.matched_vulnerabilities.length :
                          (data.ranked_vulnerabilities ? data.ranked_vulnerabilities.length : 0)));
            return {
                ...data,
                matched_count: count,
                match_report: {
                    ...(data.match_report || {}),
                    matched_count: count
                }
            };
        });

        const top5KevCount = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.top_5) return 0;
            return currentOrgData.value.top_5.filter(v => v.cisa_kev).length;
        });

        const averageRiskScore = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.top_5 || currentOrgData.value.top_5.length === 0) return '0.000';
            const sum = currentOrgData.value.top_5.reduce((acc, curr) => acc + curr.risk_score, 0);
            return (sum / currentOrgData.value.top_5.length).toFixed(3);
        });

        const allLoggedErrors = computed(() => {
            if (!backendData.value || !backendData.value.errors) return [];
            const e = backendData.value.errors;
            return [
                ...(e.org_errors || []),
                ...(e.vuln_errors || []),
                ...(e.prac_errors || [])
            ];
        });

        const totalErrorsCount = computed(() => {
            return allLoggedErrors.value.length;
        });

        const filteredFindings = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.ranked_vulnerabilities) return [];
            let list = [...currentOrgData.value.ranked_vulnerabilities];
            
            if (searchQuery.value) {
                const q = searchQuery.value.toLowerCase();
                list = list.filter(v => v.cve_id.toLowerCase().includes(q) || v.product_name.toLowerCase().includes(q));
            }
            
            if (productFilter.value) {
                list = list.filter(v => v.product_name === productFilter.value);
            }
            
            if (kevFilter.value !== '') {
                const isKev = kevFilter.value === 'true';
                list = list.filter(v => v.cisa_kev === isKev);
            }
            
            if (sortOption.value === 'risk_score') {
                list.sort((a, b) => b.risk_score - a.risk_score);
            } else if (sortOption.value === 'cvss_base_score') {
                list.sort((a, b) => (b.cvss_base_score || 0) - (a.cvss_base_score || 0));
            } else if (sortOption.value === 'first_epss') {
                list.sort((a, b) => (b.first_epss || 0) - (a.first_epss || 0));
            } else if (sortOption.value === 'cve_id') {
                list.sort((a, b) => a.cve_id.localeCompare(b.cve_id));
            }
            
            return list;
        });

        const setPage = (pageId) => {
            currentPage.value = pageId;
            mobileLayoutOpen.value = false;
            if (pageId === 'simulator' && !simulationResult.value) {
                runSimulation();
                fetchBestFirstFix();
            }
        };

        const onOrgChange = () => {
            expandedVulnCves.value.clear();
            const top5 = currentOrgData.value?.top_5 || [];
            if (top5.length > 0) {
                expandedVulnCves.value.add(top5[0].cve_id + '-' + top5[0].product_name);
            }
            fetchBestFirstFix();
            if (currentPage.value === 'simulator' || simulationResult.value) {
                runSimulation();
            }
        };

        const resetFilters = () => {
            searchQuery.value = '';
            productFilter.value = '';
            kevFilter.value = '';
            sortOption.value = 'risk_score';
        };

        const toggleVulnExpand = (cveKey) => {
            if (expandedVulnCves.value.has(cveKey)) {
                expandedVulnCves.value.delete(cveKey);
            } else {
                expandedVulnCves.value.add(cveKey);
            }
        };

        const isExpanded = (cveKey) => {
            return expandedVulnCves.value.has(cveKey);
        };

        const openModal = (vuln) => {
            selectedVulnDetail.value = vuln;
            showModal.value = true;
        };

        const closeModal = () => {
            showModal.value = false;
            selectedVulnDetail.value = null;
        };

        const toggleTheme = () => {
            theme.value = theme.value === 'dark' ? 'light' : 'dark';
            document.body.className = theme.value + '-theme';
        };

        const getSeverityLabel = (cvss) => {
            if (cvss >= 9.0) return 'CRITICAL';
            if (cvss >= 7.0) return 'HIGH';
            if (cvss >= 4.0) return 'MEDIUM';
            return 'LOW';
        };

        const getSeverityClass = (cvss) => {
            if (cvss >= 9.0) return 'severity-critical';
            if (cvss >= 7.0) return 'severity-high';
            if (cvss >= 4.0) return 'severity-medium';
            return 'severity-low';
        };

        const getOffsetClass = (diff) => {
            if (diff > 0) return 'offset-positive';
            if (diff < 0) return 'offset-negative';
            return 'offset-zero';
        };

        const getOffsetLabel = (diff) => {
            if (diff > 0) return `+${diff} Sys Rank Lower`;
            if (diff < 0) return `${diff} Sys Rank Higher`;
            return '0 Match';
        };

        const percentScale = (value, weight) => {
            if (!weight) return '0%';
            const factor = parseFloat(value) / parseFloat(weight);
            return `${(factor * 100).toFixed(1)}%`;
        };

        onMounted(() => {
            checkSavedSession();
            if (isAuthenticated.value) {
                fetchData();
                fetchAiStatus();
            }
        });

        return {
            loading,
            error,
            backendData,
            currentPage,
            selectedOrgId,
            mobileLayoutOpen,
            theme,
            navItems,
            
            // Auth exports
            isAuthenticated,
            authLoading,
            authSuccess,
            authForm,
            authErrors,
            currentUser,
            showForgotModal,
            forgotEmail,
            forgotSubmitted,
            showSignupModal,
            signupForm,
            signupSubmitted,
            handleLogin,
            handleLogout,
            fastFillDemo,
            togglePasswordVisibility,
            openForgotModal,
            closeForgotModal,
            submitForgot,
            openSignupModal,
            closeSignupModal,
            submitSignup,
            showSecurityModal,

            // AI Advisory exports
            showAiModal,
            aiLoading,
            aiError,
            aiAnalysisData,
            aiServiceStatus,
            openAiAnalysis,
            closeAiModal,

            // Upload exports
            fileInputRef,
            uploading,
            uploadError,
            uploadInspectData,
            importSuccessSummary,
            isDragOver,
            triggerChooseFile,
            onFileSelected,
            onFileDrop,
            importAndActivateDataset,
            loadDemoDataset,
            resetToBundledBaseline,

            // Simulator exports
            simulating,
            simError,
            simulationResult,
            selectedRemediatedPairs,
            bestFixLoading,
            bestFixResult,
            showSimModal,
            simModalTargetVuln,
            pairKey,
            isPairRemediated,
            toggleRemediationPair,
            openSimulationModal,
            closeSimulationModal,
            runSimulation,
            resetSimulation,
            fetchBestFirstFix,
            applyBestFixToSimulation,

            currentOrg,
            currentOrgData,
            top5KevCount,
            averageRiskScore,
            allLoggedErrors,
            totalErrorsCount,
            filteredFindings,
            
            searchQuery,
            productFilter,
            kevFilter,
            sortOption,
            
            showModal,
            selectedVulnDetail,
            
            fetchData,
            setPage,
            onOrgChange,
            resetFilters,
            
            toggleVulnExpand,
            isExpanded,
            openModal,
            closeModal,
            toggleTheme,
            
            getSeverityLabel,
            getSeverityClass,
            getOffsetClass,
            getOffsetLabel,
            percentScale
        };
    }
}).mount('#app');
