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

        // Handle Login Submission
        const handleLogin = async () => {
            if (!validateLoginForm()) {
                return;
            }

            authLoading.value = true;
            authErrors.value.general = '';

            try {
                // Realistic authentication simulation delay
                await new Promise(resolve => setTimeout(resolve, 600));

                const trimmedEmail = authForm.value.email.trim();
                
                // Formulate enterprise user profile
                const emailPrefix = trimmedEmail.split('@')[0];
                const displayName = emailPrefix
                    .replace(/[._-]/g, ' ')
                    .replace(/\b\w/g, c => c.toUpperCase());

                const userSession = {
                    name: displayName || 'SecOps Analyst',
                    email: trimmedEmail,
                    role: 'Lead Vulnerability Analyst',
                    clearance: 'LEVEL 4 - SEC-NET',
                    loginTimestamp: new Date().toISOString()
                };

                const sessionPayload = {
                    token: 'vt_sec_' + Math.random().toString(36).substring(2) + Date.now(),
                    user: userSession
                };

                if (authForm.value.rememberMe) {
                    localStorage.setItem('vulntriage_session', JSON.stringify(sessionPayload));
                } else {
                    sessionStorage.setItem('vulntriage_session', JSON.stringify(sessionPayload));
                }

                currentUser.value = userSession;
                authSuccess.value = true;

                // Brief success feedback then transition
                setTimeout(() => {
                    isAuthenticated.value = true;
                    authLoading.value = false;
                    authSuccess.value = false;
                    currentPage.value = 'dashboard';
                    
                    // Fetch backend telemetry if not yet loaded
                    if (!backendData.value) {
                        fetchData();
                    }
                }, 400);

            } catch (err) {
                authLoading.value = false;
                authErrors.value.general = 'Authentication gateway rejected credentials. Please verify your access.';
            }
        };

        // Fast-fill demo credentials
        const fastFillDemo = () => {
            authForm.value.email = 'analyst@vulntriage.sec';
            authForm.value.password = 'CyberDefense#2026';
            authErrors.value.email = '';
            authErrors.value.password = '';
            authErrors.value.general = '';
        };

        // Toggle password visibility
        const togglePasswordVisibility = () => {
            authForm.value.showPassword = !authForm.value.showPassword;
        };

        // Handle Logout
        const handleLogout = () => {
            try {
                localStorage.removeItem('vulntriage_session');
                sessionStorage.removeItem('vulntriage_session');
            } catch (e) {
                // ignore
            }
            isAuthenticated.value = false;
            authForm.value.password = '';
            authErrors.value.email = '';
            authErrors.value.password = '';
            authErrors.value.general = '';
            authSuccess.value = false;
            authLoading.value = false;
            mobileLayoutOpen.value = false;
        };

        // Modal Helpers
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
            signupForm.value = {
                name: '',
                email: authForm.value.email || '',
                organization: 'ORG-001 (Global Financial Services)',
                clearanceLevel: 'Level 2 - Standard Analyst',
                justification: ''
            };
            signupSubmitted.value = false;
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
        // EXISTING DASHBOARD APPLICATION STATE
        // ==========================================
        // Expanded CVEs tracker for collapsible cards
        const expandedVulnCves = ref(new Set());
        
        // All findings filters
        const searchQuery = ref('');
        const productFilter = ref('');
        const kevFilter = ref('');
        const sortOption = ref('risk_score');
        
        // Modal detail box state
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
                    // Expand rank 1 by default
                    expandedVulnCves.value.add(currentTop5[0].cve_id + '-' + currentTop5[0].product_name);
                }
            } catch (err) {
                console.error("Data load failure:", err);
                error.value = err.message || "Failed to establish socket feedback with backplane.";
            } finally {
                loading.value = false;
            }
        };

        // Active organization object
        const currentOrg = computed(() => {
            if (!backendData.value || !backendData.value.organizations) return null;
            return backendData.value.organizations.find(o => o.org_id === selectedOrgId.value);
        });

        // Active organization triage structures
        const currentOrgData = computed(() => {
            if (!backendData.value || !backendData.value.org_data) return null;
            return backendData.value.org_data[selectedOrgId.value];
        });

        // KEV Count inside top 5
        const top5KevCount = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.top_5) return 0;
            return currentOrgData.value.top_5.filter(v => v.cisa_kev).length;
        });

        // Average Risk Score of top prioritized vulnerabilities
        const averageRiskScore = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.top_5 || currentOrgData.value.top_5.length === 0) return '0.000000';
            const sum = currentOrgData.value.top_5.reduce((acc, curr) => acc + curr.risk_score, 0);
            return (sum / currentOrgData.value.top_5.length).toFixed(6);
        });

        // Error Diagnostics logs mapping
        const allLoggedErrors = computed(() => {
            if (!backendData.value || !backendData.value.errors) return [];
            const errs = backendData.value.errors;
            return [
                ...errs.org_errors,
                ...errs.vuln_errors,
                ...errs.prac_errors,
                ...errs.duplicates.map(c => `Duplicate combination reported for: ${c}`)
            ];
        });

        const totalErrorsCount = computed(() => {
            return allLoggedErrors.value.length;
        });

        // All matched vulnerabilities filtered table registry
        const filteredFindings = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.ranked_vulnerabilities) return [];
            let list = [...currentOrgData.value.ranked_vulnerabilities];

            // Search query filter
            if (searchQuery.value) {
                const query = searchQuery.value.toLowerCase().trim();
                list = list.filter(v => 
                    v.cve_id.toLowerCase().includes(query) || 
                    v.product_name.toLowerCase().includes(query)
                );
            }

            // Products filter
            if (productFilter.value) {
                list = list.filter(v => v.product_name === productFilter.value);
            }

            // KEV filter
            if (kevFilter.value === 'kev') {
                list = list.filter(v => v.cisa_kev);
            } else if (kevFilter.value === 'non_kev') {
                list = list.filter(v => !v.cisa_kev);
            }

            // Dynamic sort mappings (not mutating backend ranks, only frontend display sorting)
            if (sortOption.value === 'risk_score') {
                list.sort((a, b) => b.risk_score - a.risk_score);
            } else if (sortOption.value === 'cvss') {
                list.sort((a, b) => b.cvss_base_score - a.cvss_base_score);
            } else if (sortOption.value === 'epss') {
                list.sort((a, b) => b.first_epss - a.first_epss);
            }

            return list;
        });

        // Page change handler
        const setPage = (pageName) => {
            currentPage.value = pageName;
            mobileLayoutOpen.value = false;
        };

        // Org swap handler
        const onOrgChange = () => {
            // Recapture default expand for index 0 of current org
            expandedVulnCves.value.clear();
            if (currentOrgData.value && currentOrgData.value.top_5 && currentOrgData.value.top_5.length > 0) {
                expandedVulnCves.value.add(currentOrgData.value.top_5[0].cve_id + '-' + currentOrgData.value.top_5[0].product_name);
            }
            // Reset searches
            productFilter.value = '';
            searchQuery.value = '';
            kevFilter.value = '';
        };

        const resetFilters = () => {
            searchQuery.value = '';
            productFilter.value = '';
            kevFilter.value = '';
        };

        // Expand/Collapse cards
        const toggleVulnExpand = (cveId) => {
            if (expandedVulnCves.value.has(cveId)) {
                expandedVulnCves.value.delete(cveId);
            } else {
                expandedVulnCves.value.add(cveId);
            }
        };

        const isExpanded = (cveId) => {
            return expandedVulnCves.value.has(cveId);
        };

        // Modals detail toggles
        const openModal = (vuln) => {
            selectedVulnDetail.value = vuln;
            showModal.value = true;
        };

        const closeModal = () => {
            showModal.value = false;
            selectedVulnDetail.value = null;
        };

        // Theme controllers
        const toggleTheme = () => {
            theme.value = theme.value === 'dark' ? 'light' : 'dark';
            document.body.classList.toggle('light-theme', theme.value === 'light');
            document.body.classList.toggle('cyber-theme', theme.value === 'dark');
        };

        // Severity utility helper mappings
        const getSeverityLabel = (cvss) => {
            const val = parseFloat(cvss);
            if (val >= 9.0) return 'CRITICAL';
            if (val >= 7.0) return 'HIGH';
            if (val >= 4.0) return 'MEDIUM';
            return 'LOW';
        };

        const getSeverityClass = (cvss) => {
            const val = parseFloat(cvss);
            if (val >= 9.0) return 'severity-critical';
            if (val >= 7.0) return 'severity-high';
            if (val >= 4.0) return 'severity-medium';
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

        // Helper to output dynamic scaling percentage of contribution weights
        const percentScale = (value, weight) => {
            if (!weight) return '0%';
            const factor = parseFloat(value) / parseFloat(weight);
            return `${(factor * 100).toFixed(1)}%`;
        };

        onMounted(() => {
            checkSavedSession();
            fetchData();
            fetchAiStatus();
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

            // AI Advisory exports
            showAiModal,
            aiLoading,
            aiError,
            aiAnalysisData,
            aiServiceStatus,
            openAiAnalysis,
            closeAiModal,

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
