/**
 * Bitcoin Script Explainer - Frontend JavaScript
 * 
 * Handles user interaction and API communication for the script explainer.
 */

// DOM Elements
const scriptInput = document.getElementById('scriptInput');
const explainBtn = document.getElementById('explainBtn');
const loadExampleBtn = document.getElementById('loadExample');
const outputSection = document.getElementById('outputSection');
const loading = document.getElementById('loading');
const errorMessage = document.getElementById('errorMessage');
const errorText = document.getElementById('errorText');
const results = document.getElementById('results');
const scriptType = document.getElementById('scriptType');
const stepsContainer = document.getElementById('stepsContainer');
const summary = document.getElementById('summary');

// Example scripts for demonstration
const exampleScripts = [
    'OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG',
    'OP_HASH160 89abcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUAL',
    'OP_RETURN 48656c6c6f20426974636f696e21',
    '2 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 2 OP_CHECKMULTISIG',
    '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f OP_CHECKSIG'
];

let currentExampleIndex = 0;

/**
 * Initialize event listeners
 */
function init() {
    explainBtn.addEventListener('click', handleExplainClick);
    loadExampleBtn.addEventListener('click', handleLoadExample);

    // Also allow Enter key (with Ctrl/Cmd) to submit
    scriptInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            handleExplainClick();
        }
    });
}

/**
 * Handle the explain button click
 */
async function handleExplainClick() {
    const script = scriptInput.value.trim();

    if (!script) {
        showError('Please enter a Bitcoin Script to explain.');
        return;
    }

    await explainScript(script);
}

/**
 * Load an example script into the input
 */
function handleLoadExample() {
    scriptInput.value = exampleScripts[currentExampleIndex];
    currentExampleIndex = (currentExampleIndex + 1) % exampleScripts.length;

    // Clear any previous results
    hideAllStates();
}

/**
 * Call the API to explain the script
 * @param {string} script - The Bitcoin script in ASM format
 */
async function explainScript(script) {
    hideAllStates();
    showLoading();

    try {
        const response = await fetch('/explain', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ script: script }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Failed to explain script');
        }

        displayResults(data);

    } catch (error) {
        showError(error.message || 'An error occurred while explaining the script.');
    } finally {
        hideLoading();
    }
}

/**
 * Display the explanation results
 * @param {Object} data - The API response data
 */
function displayResults(data) {
    // Display script type
    scriptType.textContent = data.script_type;

    // Display steps
    stepsContainer.innerHTML = '';
    data.steps.forEach((step, index) => {
        const stepElement = createStepElement(step, index);
        stepsContainer.appendChild(stepElement);
    });

    // Display summary
    summary.textContent = data.summary;

    // Show results
    results.classList.add('visible');
}

/**
 * Create a step element for the execution display
 * @param {Object} step - Step data from the API
 * @param {number} index - Step index
 * @returns {HTMLElement} The step element
 */
function createStepElement(step, index) {
    const stepDiv = document.createElement('div');
    stepDiv.className = 'step';

    const stackBeforeStr = step.stack_before.length > 0
        ? step.stack_before.join(' | ')
        : '';

    const stackAfterStr = step.stack_after.length > 0
        ? step.stack_after.join(' | ')
        : '';

    stepDiv.innerHTML = `
        <div class="step-header">
            <span class="step-number">${index + 1}</span>
            <span class="step-opcode">${escapeHtml(step.opcode)}</span>
        </div>
        <div class="step-explanation">${escapeHtml(step.explanation)}</div>
        <div class="step-stacks">
            <div class="stack-display">
                <div class="stack-label">Stack Before</div>
                <div class="stack-items ${!stackBeforeStr ? 'stack-empty' : ''}">
                    ${stackBeforeStr ? escapeHtml(stackBeforeStr) : '(empty)'}
                </div>
            </div>
            <div class="stack-display">
                <div class="stack-label">Stack After</div>
                <div class="stack-items ${!stackAfterStr ? 'stack-empty' : ''}">
                    ${stackAfterStr ? escapeHtml(stackAfterStr) : '(empty)'}
                </div>
            </div>
        </div>
    `;

    return stepDiv;
}

/**
 * Show loading state
 */
function showLoading() {
    loading.classList.add('visible');
}

/**
 * Hide loading state
 */
function hideLoading() {
    loading.classList.remove('visible');
}

/**
 * Show error message
 * @param {string} message - Error message to display
 */
function showError(message) {
    errorText.textContent = message;
    errorMessage.classList.add('visible');
}

/**
 * Hide all output states
 */
function hideAllStates() {
    loading.classList.remove('visible');
    errorMessage.classList.remove('visible');
    results.classList.remove('visible');
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
