const { createApp, ref, computed, onMounted } = Vue;

createApp({
    setup() {
        const loading = ref(true);
        const error = ref(null);
        const backendData = ref(null);
        
        const currentPage = ref('dashboard');
        const selectedOrgId = ref('ORG-001');
        const mobileLayoutOpen = ref(false);
        const theme = ref('dark');
        
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
            fetchData();
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
