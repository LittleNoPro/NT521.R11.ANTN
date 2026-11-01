/**
 * log-parser.js
 * Extracts tool calls from CVE reproduction logs
 */

const LOG_SECTION_BOUNDS = {
    'preReqsBuilder': { start: '- a) 📋 Pre-Requsites Builder', end: '- b) 🏭 Repository Builder' },
    'repositoryBuilder': { start: '- b) 🏭 Repository Builder', end: '👀 Running Critic on Repo Builder' },
    'exploitDeveloper': { start: '# 6) 🚀 Running Exploiter', end: '### HUMAN INPUT SECTION ###' },
    'verifierDeveloper': { start: '- b) 🛡️ CTF Verifier', end: '- c) 🎯 Validator' }
};

/**
 * Extract tool calls from a log file for a specific submodule
 * @param {string} logContent - The full log file content
 * @param {string} subModuleName - The submodule ID (e.g., 'preReqsBuilder')
 * @returns {Array|null} Array of tool call objects or null if not found
 */
function extractToolCallsFromLog(logContent, subModuleName) {
    const bounds = LOG_SECTION_BOUNDS[subModuleName];

    if (!bounds || !logContent) {
        console.log('No section bounds or log content for', subModuleName);
        return null;
    }

    // Extract the section between start and end markers
    const startIdx = logContent.indexOf(bounds.start);
    const endIdx = logContent.indexOf(bounds.end, startIdx);

    if (startIdx === -1 || endIdx === -1) {
        console.log('Could not find section boundaries for', subModuleName);
        return null;
    }

    const subLogs = logContent.substring(startIdx, endIdx);
    const toolCalls = [];

    // Parse "Invoking: `tool_name` with `tool_args`" pattern
    const lines = subLogs.split('\n');
    let currentToolCall = null;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.trim().startsWith('Invoking:')) {
            // Save previous tool call if exists
            if (currentToolCall) {
                toolCalls.push(currentToolCall);
            }

            // Pattern: Invoking: `tool_name` with `tool_args`
            const match = line.match(/Invoking:\s*`([^`]+)`\s+with\s+`([^`]+)`/);
            if (match) {
                const toolName = match[1];
                const toolArgsStr = match[2];

                try {
                    // Parse the arguments (they're in Python dict format)
                    let argsJson = toolArgsStr
                        .replace(/'/g, '"')  // Replace single quotes with double quotes
                        .replace(/\bTrue\b/g, 'true')
                        .replace(/\bFalse\b/g, 'false')
                        .replace(/\bNone\b/g, 'null');

                    const toolArgs = JSON.parse(argsJson);

                    currentToolCall = {
                        name: toolName,
                        arguments: toolArgs,
                        output: ''
                    };
                } catch (e) {
                    console.log('Error parsing tool args for', toolName, ':', e);
                    currentToolCall = null;
                }
            }
        } else if (currentToolCall) {
            // Accumulate output lines for current tool call
            // Stop accumulating when we hit the next Invoking: line or section marker
            if (!line.trim().startsWith('Invoking:') &&
                !line.includes('### HUMAN INPUT') &&
                !line.includes('Running Critic')) {
                currentToolCall.output += line + '\n';
            }
        }
    }

    // Don't forget the last tool call
    if (currentToolCall) {
        toolCalls.push(currentToolCall);
    }

    console.log('Found', toolCalls.length, 'tool calls for', subModuleName);
    return toolCalls.length > 0 ? toolCalls : null;
}
