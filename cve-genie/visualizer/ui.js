/**
 * ui.js
 * UI rendering functions for the CVE visualizer
 */

/**
 * Escape HTML to prevent XSS attacks
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

/**
 * Switch between tabs
 * @param {string} tabName - The tab name to switch to
 */
function switchTab(tabName) {
    // Hide all panes
    const panes = document.querySelectorAll('[data-pane]');
    panes.forEach(pane => pane.style.display = 'none');

    // Remove active class from all tabs
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => tab.classList.remove('active'));

    // Show selected pane and mark tab as active
    const selectedPane = document.querySelector(`[data-pane="${tabName}"]`);
    if (selectedPane) {
        selectedPane.style.display = 'block';
    }

    const selectedTab = document.querySelector(`.tab[data-tab="${tabName}"]`);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }
}

/**
 * Create or get a tab pane
 * @param {string} tabName - The tab name
 * @returns {HTMLElement} The tab pane element
 */
function createTabPane(tabName) {
    let pane = document.querySelector(`[data-pane="${tabName}"]`);
    if (!pane) {
        const panelContent = document.getElementById('panel-content');
        pane = document.createElement('div');
        pane.setAttribute('data-pane', tabName);
        pane.style.display = 'none';
        panelContent.appendChild(pane);
    }
    return pane;
}

/**
 * Render tool calls in the Tool Calls tab
 * @param {Array} toolCalls - Array of tool call objects
 */
function renderToolCallsContent(toolCalls) {
    let html = '';

    if (toolCalls && Array.isArray(toolCalls)) {
        for (const call of toolCalls) {
            html += '<div class="tool-call">';
            if (call.name) {
                html += `<div class="tool-call-name">${escapeHtml(call.name)}</div>`;
            }
            if (call.arguments) {
                html += '<div class="tool-call-section"><div class="tool-call-label">Arguments:</div>';
                const args = typeof call.arguments === 'string' ? JSON.parse(call.arguments) : call.arguments;
                for (const [key, value] of Object.entries(args)) {
                    html += `
                        <div class="tool-call-arg">
                            <span class="tool-call-arg-key">${escapeHtml(key)}:</span>
                            ${escapeHtml(typeof value === 'object' ? JSON.stringify(value) : String(value))}
                        </div>
                    `;
                }
                html += '</div>';
            }
            if (call.output && call.output.trim().length > 0) {
                html += '<div class="tool-call-section"><div class="tool-call-label">Output:</div>';
                html += `<div class="field-value code-block">${escapeHtml(call.output)}</div>`;
                html += '</div>';
            }
            html += '</div>';
        }
    } else {
        html = '<div class="no-data">No tool calls found</div>';
    }

    const toolCallsPane = createTabPane('tool-calls');
    toolCallsPane.innerHTML = html;
    console.log('Rendered tool calls pane');
}

/**
 * Render results in the Results tab
 * @param {*} data - The data to render
 */
function renderResultsContent(data) {
    let html = '';

    if (typeof data === 'string') {
        html = `<div class="field"><div class="field-value">${escapeHtml(data)}</div></div>`;
    } else if (typeof data === 'object') {
        const fieldOrder = ['overview', 'success', 'exploit', 'poc', 'decision', 'analysis', 'description', 'feedback', 'issues', 'review', 'files', 'services', 'output', 'steps_to_fix'];

        // Show ordered fields first
        for (const key of fieldOrder) {
            if (data[key]) {
                const value = data[key];
                html += `<div class="field">
                    <div class="field-name">${escapeHtml(key)}:</div>
                    <div class="field-value code-block">${escapeHtml(typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value))}</div>
                </div>`;
            }
        }

        // Show remaining fields
        for (const [key, value] of Object.entries(data)) {
            if (!fieldOrder.includes(key)) {
                html += `<div class="field">
                    <div class="field-name">${escapeHtml(key)}:</div>
                    <div class="field-value code-block">${escapeHtml(typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value))}</div>
                </div>`;
            }
        }
    }

    const resultsPane = createTabPane('results');
    resultsPane.innerHTML = html;
    console.log('Rendered results pane');
}

/**
 * Render the right panel for a selected submodule
 * @param {Object} subData - The submodule data
 * @param {string} selectedModule - The selected module ID
 * @param {string} selectedSubModule - The selected submodule ID
 */
function renderPanelContent(subData, selectedModule, selectedSubModule) {
    const panelContent = document.getElementById('panelContent');
    const tabContainer = document.getElementById('tabContainer');

    // Clear previous content
    tabContainer.innerHTML = '';
    const panes = document.querySelectorAll('[data-pane]');
    panes.forEach(pane => pane.remove());

    if (!subData.loaded) {
        panelContent.innerHTML = '<div class="no-data">No data available for this module</div>';
        return;
    }

    const hasToolCallsTab = !['dataProcessor', 'knowledgeBuilder', 'repoCritic', 'exploitCritic', 'verifierCritic'].includes(selectedSubModule);

    // Create tabs
    if (hasToolCallsTab) {
        tabContainer.innerHTML += '<button class="tab active" data-tab="tool-calls" onclick="switchTab(\'tool-calls\')">🔧 Tool Calls</button>';
    }
    tabContainer.innerHTML += '<button class="tab ' + (hasToolCallsTab ? '' : 'active') + '" data-tab="results" onclick="switchTab(\'results\')">📊 Results</button>';
    tabContainer.style.display = 'flex';

    if (hasToolCallsTab) {
        const logToolCalls = extractToolCallsFromLog(window.logContent, selectedSubModule);
        console.log('Log tool calls for', selectedSubModule, ':', logToolCalls);
        const toolCalls = logToolCalls || (typeof subData.data === 'object' && subData.data.tool_calls ? subData.data.tool_calls : null);
        renderToolCallsContent(toolCalls);
    }
    renderResultsContent(subData.data);

    // Show appropriate tab by default
    switchTab(hasToolCallsTab ? 'tool-calls' : 'results');
}
