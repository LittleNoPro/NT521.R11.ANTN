/**
 * data-loader.js
 * Handles loading CVE data and log files
 */

/**
 * Load CVE data from the server
 * @param {string} cveName - The CVE name (e.g., 'CVE-2024-5129')
 * @returns {Promise<Object>} Object containing loaded data
 */
async function loadCVEData(cveName) {
    const basePath = `/results/reproduced_cves/${cveName}`;
    const data = {};

    // Load cve_info.json
    try {
        const response = await fetch(`${basePath}/cve_info.json`);
        if (response.ok) {
            data.cveInfo = await response.json();
            console.log('Loaded cve_info.json');
        }
    } catch (error) {
        console.error('Error loading cve_info.json:', error);
    }

    // Load knowledge_builder.txt
    try {
        const response = await fetch(`${basePath}/knowledge_builder.txt`);
        if (response.ok) {
            data.knowledgeBuilder = await response.text();
            console.log('Loaded knowledge_builder.txt');
        }
    } catch (error) {
        console.error('Error loading knowledge_builder.txt:', error);
    }

    // Load pre_req_builder.json
    try {
        const response = await fetch(`${basePath}/pre_req_builder.json`);
        if (response.ok) {
            data.preReqBuilder = await response.json();
            console.log('Loaded pre_req_builder.json');
        }
    } catch (error) {
        console.error('Error loading pre_req_builder.json:', error);
    }

    // Load repo_builder.json
    try {
        const response = await fetch(`${basePath}/repo_builder.json`);
        if (response.ok) {
            data.repoBuilder = await response.json();
            console.log('Loaded repo_builder.json');
        }
    } catch (error) {
        console.error('Error loading repo_builder.json:', error);
    }

    // Load repo_critic.json
    try {
        const response = await fetch(`${basePath}/repo_critic.json`);
        if (response.ok) {
            data.repoCritic = await response.json();
            console.log('Loaded repo_critic.json');
        }
    } catch (error) {
        console.error('Error loading repo_critic.json:', error);
    }

    // Load exploit_developer.json
    try {
        const response = await fetch(`${basePath}/exploit_developer.json`);
        if (response.ok) {
            data.exploitDeveloper = await response.json();
            console.log('Loaded exploit_developer.json');
        }
    } catch (error) {
        console.error('Error loading exploit_developer.json:', error);
    }

    // Load exploit_critic.json
    try {
        const response = await fetch(`${basePath}/exploit_critic.json`);
        if (response.ok) {
            data.exploitCritic = await response.json();
            console.log('Loaded exploit_critic.json');
        }
    } catch (error) {
        console.error('Error loading exploit_critic.json:', error);
    }

    // Load ctf_verifier.json
    try {
        const response = await fetch(`${basePath}/ctf_verifier.json`);
        if (response.ok) {
            data.ctfVerifier = await response.json();
            console.log('Loaded ctf_verifier.json');
        }
    } catch (error) {
        console.error('Error loading ctf_verifier.json:', error);
    }

    // Load verifier_critic.json
    try {
        const response = await fetch(`${basePath}/verifier_critic.json`);
        if (response.ok) {
            data.verifierCritic = await response.json();
            console.log('Loaded verifier_critic.json');
        }
    } catch (error) {
        console.error('Error loading verifier_critic.json:', error);
    }

    // Load log.txt
    try {
        const response = await fetch(`${basePath}/log.txt`);
        if (response.ok) {
            window.logContent = await response.text();
            console.log('Loaded log.txt');
        }
    } catch (error) {
        console.error('Error loading log.txt:', error);
    }

    return data;
}

/**
 * Combine loader and UI functions to load a CVE
 * @param {string} cveName - The CVE name
 */
async function loadCVE(cveName) {
    const errorMsg = document.getElementById('error-msg');
    errorMsg.style.display = 'none';

    try {
        const data = await loadCVEData(cveName);
        console.log('Successfully loaded CVE data');
        initializeVisualization(data, cveName);
    } catch (error) {
        console.error('Error loading CVE:', error);
        errorMsg.textContent = `Error loading CVE: ${error.message}`;
        errorMsg.style.display = 'block';
    }
}
