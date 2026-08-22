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
                await new Promise(resolve => setTimeout(resolve, 600));

                const trimmedEmail = authForm.value.email.trim();
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

                setTimeout(() => {
                    isAuthenticated.value = true;
                    authLoading.value = false;
                    authSuccess.value = false;
                    currentPage.value = 'dashboard';
                    
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
        // FEATHERLESS.AI THREAT INTELLIGENCE & COPILOT
        // ==========================================
        const featherlessApiKey = ref(localStorage.getItem('vt_featherless_api_key') || '');
        const selectedAiModel = ref(localStorage.getItem('vt_featherless_model') || 'meta-llama/Meta-Llama-3.1-8B-Instruct');
        const aiAvailableModels = ref([
            { id: 'meta-llama/Meta-Llama-3.1-8B-Instruct', name: 'Llama 3.1 8B Instruct (Meta - Fast & Accurate)' },
            { id: 'mistralai/Mistral-7B-Instruct-v0.3', name: 'Mistral 7B Instruct v0.3 (Mistral AI)' },
            { id: 'Qwen/Qwen2.5-7B-Instruct', name: 'Qwen 2.5 7B Instruct (Alibaba)' },
            { id: 'deepseek-ai/DeepSeek-R1-Distill-Qwen-8B', name: 'DeepSeek R1 Distill Qwen 8B (Reasoning Engine)' }
        ]);
        const hasServerEnvKey = ref(false);
        const showAiSettingsModal = ref(false);
        const tempApiKey = ref('');
        const tempAiModel = ref('');
        const aiSettingsSaved = ref(false);

        // AI Playbook State
        const showPlaybookModal = ref(false);
        const selectedPlaybookVuln = ref(null);
        const activePlaybook = ref(null);
        const playbookLoading = ref(false);
        const playbookError = ref(null);
        const playbookCopied = ref(false);

        // AI Copilot Drawer State
        const showCopilotDrawer = ref(false);
        const copilotInput = ref('');
        const copilotLoading = ref(false);
        const copilotMessages = ref([
            {
                role: 'assistant',
                content: '🛡️ **VULNTRIAGE AI Copilot initialized.** I have loaded your organization context and active vulnerability priorities. Ask me anything about risk mitigation, emergency workarounds, or attack vectors.'
            }
        ]);

        // Fetch models & key status from server
        const fetchAiConfig = async () => {
            try {
                const res = await fetch('/api/ai/models');
                if (res.ok) {
                    const data = await res.json();
                    if (data.models && data.models.length > 0) {
                        aiAvailableModels.value = data.models;
                    }
                    hasServerEnvKey.value = data.has_env_key || false;
                }
            } catch (e) {
                // ignore
            }
        };

        const openAiSettings = () => {
            tempApiKey.value = featherlessApiKey.value;
            tempAiModel.value = selectedAiModel.value;
            aiSettingsSaved.value = false;
            showAiSettingsModal.value = true;
        };

        const closeAiSettings = () => {
            showAiSettingsModal.value = false;
            aiSettingsSaved.value = false;
        };

        const saveAiSettings = () => {
            featherlessApiKey.value = tempApiKey.value.trim();
            selectedAiModel.value = tempAiModel.value;
            localStorage.setItem('vt_featherless_api_key', featherlessApiKey.value);
            localStorage.setItem('vt_featherless_model', selectedAiModel.value);
            aiSettingsSaved.value = true;
            setTimeout(() => {
                showAiSettingsModal.value = false;
                aiSettingsSaved.value = false;
            }, 1000);
        };

        // Generate AI Playbook
        const generateAiPlaybook = async (vuln) => {
            selectedPlaybookVuln.value = vuln;
            showPlaybookModal.value = true;
            playbookLoading.value = true;
            playbookError.value = null;
            activePlaybook.value = null;
            playbookCopied.value = false;

            try {
                const payload = {
                    vuln: vuln,
                    org: currentOrg.value,
                    api_key: featherlessApiKey.value,
                    model: selectedAiModel.value
                };

                const res = await fetch('/api/ai/playbook', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await res.json();
                if (data.success) {
                    activePlaybook.value = data;
                } else {
                    playbookError.value = data.error || 'Failed to generate AI playbook.';
                }
            } catch (err) {
                playbookError.value = 'Network error connecting to AI analysis engine.';
            } finally {
                playbookLoading.value = false;
            }
        };

        const closePlaybookModal = () => {
            showPlaybookModal.value = false;
            selectedPlaybookVuln.value = null;
            activePlaybook.value = null;
            playbookError.value = null;
        };

        const copyPlaybookToClipboard = () => {
            if (!activePlaybook.value || !activePlaybook.value.playbook) return;
            navigator.clipboard.writeText(activePlaybook.value.playbook);
            playbookCopied.value = true;
            setTimeout(() => {
                playbookCopied.value = false;
            }, 2000);
        };

        // Copilot Chat
        const toggleCopilotDrawer = () => {
            showCopilotDrawer.value = !showCopilotDrawer.value;
        };

        const sendCopilotMessage = async (customQuery = null) => {
            const queryText = (customQuery || copilotInput.value || '').trim();
            if (!queryText || copilotLoading.value) return;

            copilotMessages.value.push({ role: 'user', content: queryText });
            copilotInput.value = '';
            copilotLoading.value = true;

            try {
                // Focus on selected detail vuln or top 1
                const currentVuln = selectedVulnDetail.value || (currentOrgData.value?.top_5 ? currentOrgData.value.top_5[0] : null);

                const history = copilotMessages.value
                    .filter(m => m.role === 'user' || m.role === 'assistant')
                    .map(m => ({ role: m.role, content: m.content }));

                const payload = {
                    query: queryText,
                    vuln: currentVuln,
                    org: currentOrg.value,
                    history: history,
                    api_key: featherlessApiKey.value,
                    model: selectedAiModel.value
                };

                const res = await fetch('/api/ai/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await res.json();
                if (data.success && data.reply) {
                    copilotMessages.value.push({ role: 'assistant', content: data.reply });
                } else {
                    copilotMessages.value.push({
                        role: 'assistant',
                        content: `⚠️ **AI Copilot Error:** ${data.error || 'Could not process query. Please check your Featherless API key.'}`
                    });
                }
            } catch (err) {
                copilotMessages.value.push({
                    role: 'assistant',
                    content: '⚠️ **Network connection error.** Unable to connect to AI gateway.'
                });
            } finally {
                copilotLoading.value = false;
            }
        };

        const clearCopilotChat = () => {
            copilotMessages.value = [
                {
                    role: 'assistant',
                    content: '🛡️ **Chat session reset.** Ready for new cyber defense queries.'
                }
            ];
        };

        // Safe client-side Markdown to HTML Formatter
        const formatMarkdown = (md) => {
            if (!md) return '';
            let html = md
                // Escape raw HTML characters
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                // Code blocks ```code```
                .replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, '<pre class="cyber-code-block"><code class="lang-$1">$2</code></pre>')
                // Inline code `code`
                .replace(/`([^`]+)`/g, '<code class="cyber-inline-code">$1</code>')
                // Headings
                .replace(/^### (.*$)/gim, '<h4 class="ai-heading-3">$1</h4>')
                .replace(/^## (.*$)/gim, '<h3 class="ai-heading-2">$1</h3>')
                .replace(/^# (.*$)/gim, '<h2 class="ai-heading-1">$1</h2>')
                // Bold & Italic
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                // Blockquotes
                .replace(/^\> (.*$)/gim, '<blockquote class="ai-quote-box">$1</blockquote>')
                // Bullet points
                .replace(/^\s*[\-\*]\s+(.*)$/gim, '<li class="ai-list-item">$1</li>')
                // Line breaks
                .replace(/\n\n/g, '<br/><br/>');

            return html;
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
                
                const currentTop5 = data.org_data[selectedOrgId.value]?.top_5 || [];
                expandedVulnCves.value.clear();
                if (currentTop5.length > 0) {
                    expandedVulnCves.value.add(currentTop5[0].cve_id + '-' + currentTop5[0].product_name);
                }
            } catch (err) {
                console.error("Data load failure:", err);
                error.value = err.message || "Failed to establish socket feedback with backplane.";
            } finally {
                loading.value = false;
            }
        };

        const defaultOrg = {
            org_id: 'ORG-001',
            name: 'Global Retail Bank',
            sector: 'Financial Services',
            risk_appetite: 'Low',
            critical_products: ['Core Banking Framework', 'Identity Provider SaaS'],
            weight_modifiers: { cvss_weight: 0.3, cisa_kev_weight: 0.45, first_epss_weight: 0.25 }
        };

        const defaultOrgData = {
            critical_products: ['Core Banking Framework', 'Identity Provider SaaS'],
            weight_modifiers: { cvss_weight: 0.3, cisa_kev_weight: 0.45, first_epss_weight: 0.25 },
            match_report: { matched_count: 0, zero_match_products: [], product_matches_count: {} },
            top_5: [],
            ranked_vulnerabilities: []
        };

        const organizationsList = computed(() => {
            return backendData.value?.organizations || [defaultOrg];
        });

        const currentOrg = computed(() => {
            if (!backendData.value || !backendData.value.organizations) return defaultOrg;
            return backendData.value.organizations.find(o => o.org_id === selectedOrgId.value) || defaultOrg;
        });

        const currentOrgData = computed(() => {
            if (!backendData.value || !backendData.value.org_data) return defaultOrgData;
            return backendData.value.org_data[selectedOrgId.value] || defaultOrgData;
        });

        const top5KevCount = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.top_5) return 0;
            return currentOrgData.value.top_5.filter(v => v.cisa_kev).length;
        });

        const averageRiskScore = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.top_5 || currentOrgData.value.top_5.length === 0) return '0.000000';
            const sum = currentOrgData.value.top_5.reduce((acc, curr) => acc + curr.risk_score, 0);
            return (sum / currentOrgData.value.top_5.length).toFixed(6);
        });

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

        const filteredFindings = computed(() => {
            if (!currentOrgData.value || !currentOrgData.value.ranked_vulnerabilities) return [];
            let list = [...currentOrgData.value.ranked_vulnerabilities];

            if (searchQuery.value) {
                const query = searchQuery.value.toLowerCase().trim();
                list = list.filter(v => 
                    v.cve_id.toLowerCase().includes(query) || 
                    v.product_name.toLowerCase().includes(query)
                );
            }

            if (productFilter.value) {
                list = list.filter(v => v.product_name === productFilter.value);
            }

            if (kevFilter.value === 'kev') {
                list = list.filter(v => v.cisa_kev);
            } else if (kevFilter.value === 'non_kev') {
                list = list.filter(v => !v.cisa_kev);
            }

            if (sortOption.value === 'risk_score') {
                list.sort((a, b) => b.risk_score - a.risk_score);
            } else if (sortOption.value === 'cvss') {
                list.sort((a, b) => b.cvss_base_score - a.cvss_base_score);
            } else if (sortOption.value === 'epss') {
                list.sort((a, b) => b.first_epss - a.first_epss);
            }

            return list;
        });

        const setPage = (pageName) => {
            currentPage.value = pageName;
            mobileLayoutOpen.value = false;
        };

        const onOrgChange = () => {
            expandedVulnCves.value.clear();
            if (currentOrgData.value && currentOrgData.value.top_5 && currentOrgData.value.top_5.length > 0) {
                expandedVulnCves.value.add(currentOrgData.value.top_5[0].cve_id + '-' + currentOrgData.value.top_5[0].product_name);
            }
            productFilter.value = '';
            searchQuery.value = '';
            kevFilter.value = '';
        };

        const resetFilters = () => {
            searchQuery.value = '';
            productFilter.value = '';
            kevFilter.value = '';
        };

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
            document.body.classList.toggle('light-theme', theme.value === 'light');
            document.body.classList.toggle('cyber-theme', theme.value === 'dark');
        };

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

        const percentScale = (value, weight) => {
            if (!weight) return '0%';
            const factor = parseFloat(value) / parseFloat(weight);
            return `${(factor * 100).toFixed(1)}%`;
        };

        onMounted(() => {
            checkSavedSession();
            fetchData();
            fetchAiConfig();
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

            // Featherless AI exports
            featherlessApiKey,
            selectedAiModel,
            aiAvailableModels,
            hasServerEnvKey,
            showAiSettingsModal,
            tempApiKey,
            tempAiModel,
            aiSettingsSaved,
            openAiSettings,
            closeAiSettings,
            saveAiSettings,
            showPlaybookModal,
            selectedPlaybookVuln,
            activePlaybook,
            playbookLoading,
            playbookError,
            playbookCopied,
            generateAiPlaybook,
            closePlaybookModal,
            copyPlaybookToClipboard,
            showCopilotDrawer,
            copilotInput,
            copilotLoading,
            copilotMessages,
            toggleCopilotDrawer,
            sendCopilotMessage,
            clearCopilotChat,
            formatMarkdown,

            organizationsList,
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
