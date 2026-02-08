/**
 * Bitcoin Script Explainer - Cosmos Solar System UI
 */

// ============================================
// Anonymous Usage Tracking (Privacy-Safe)
// ============================================

/**
 * Generate a UUID v4 for anonymous session tracking.
 */
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * Get or create anonymous session ID.
 */
function getSessionId() {
    let sessionId = sessionStorage.getItem('btc_session_id');
    if (!sessionId) {
        sessionId = generateUUID();
        sessionStorage.setItem('btc_session_id', sessionId);
    }
    return sessionId;
}

/**
 * Track an anonymous event.
 */
async function trackEvent(eventType) {
    try {
        await fetch('/track', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: getSessionId(),
                event_type: eventType
            })
        });
    } catch (error) {
        console.debug('Tracking failed:', error);
    }
}

/**
 * Fetch and update live stats display.
 */
async function updateLiveStats() {
    try {
        const response = await fetch('/stats');
        if (response.ok) {
            const data = await response.json();
            const lifetimeEl = document.getElementById('lifetimeViews');
            const activeEl = document.getElementById('activeUsers');
            if (lifetimeEl) lifetimeEl.textContent = data.lifetime_views;
            if (activeEl) activeEl.textContent = data.current_active_users;
        }
    } catch (error) {
        console.debug('Stats update failed:', error);
    }
}

// Initialize tracking on page load
window.addEventListener('load', () => {
    trackEvent('page_visit');
    updateLiveStats();
    setInterval(updateLiveStats, 30000);
});

// DOM Elements
const scriptInput = document.getElementById('scriptInput');
const explainBtn = document.getElementById('explainBtn');
const loadExampleBtn = document.getElementById('loadExample');
const loading = document.getElementById('loading');
const errorMessage = document.getElementById('errorMessage');
const errorText = document.getElementById('errorText');
const results = document.getElementById('results');
const scriptType = document.getElementById('scriptType');
const stepsContainer = document.getElementById('stepsContainer');
const summary = document.getElementById('summary');
const stepCounter = document.getElementById('stepCounter');
const prevStepBtn = document.getElementById('prevStep');
const nextStepBtn = document.getElementById('nextStep');
const copyResultBtn = document.getElementById('copyResult');
const opcodeSearch = document.getElementById('opcodeSearch');
const opcodesGrid = document.getElementById('opcodesGrid');

// Opcode Data
const opcodeData = [
    { name: "OP_DUP", desc: "Duplicates top stack item", category: "stack" },
    { name: "OP_DROP", desc: "Removes top stack item", category: "stack" },
    { name: "OP_SWAP", desc: "Swaps top two items", category: "stack" },
    { name: "OP_ROT", desc: "Rotates top three items", category: "stack" },
    { name: "OP_OVER", desc: "Copies second item to top", category: "stack" },
    { name: "OP_NIP", desc: "Removes second item", category: "stack" },
    { name: "OP_TUCK", desc: "Copies top below second", category: "stack" },
    { name: "OP_2DUP", desc: "Duplicates top two items", category: "stack" },
    { name: "OP_3DUP", desc: "Duplicates top three items", category: "stack" },
    { name: "OP_2DROP", desc: "Removes top two items", category: "stack" },
    { name: "OP_DEPTH", desc: "Pushes stack size", category: "stack" },
    { name: "OP_SIZE", desc: "Pushes size of top item", category: "stack" },
    { name: "OP_ADD", desc: "Adds top two items", category: "arithmetic" },
    { name: "OP_SUB", desc: "Subtracts top from second", category: "arithmetic" },
    { name: "OP_1ADD", desc: "Adds 1 to top item", category: "arithmetic" },
    { name: "OP_1SUB", desc: "Subtracts 1 from top", category: "arithmetic" },
    { name: "OP_NEGATE", desc: "Negates top item", category: "arithmetic" },
    { name: "OP_ABS", desc: "Absolute value", category: "arithmetic" },
    { name: "OP_MIN", desc: "Returns smaller value", category: "arithmetic" },
    { name: "OP_MAX", desc: "Returns larger value", category: "arithmetic" },
    { name: "OP_HASH160", desc: "RIPEMD160(SHA256(x))", category: "crypto" },
    { name: "OP_SHA256", desc: "SHA-256 hash", category: "crypto" },
    { name: "OP_SHA1", desc: "SHA-1 hash", category: "crypto" },
    { name: "OP_RIPEMD160", desc: "RIPEMD-160 hash", category: "crypto" },
    { name: "OP_HASH256", desc: "Double SHA-256", category: "crypto" },
    { name: "OP_CHECKSIG", desc: "Verifies signature", category: "crypto" },
    { name: "OP_CHECKSIGVERIFY", desc: "Verify sig and fail if false", category: "crypto" },
    { name: "OP_CHECKMULTISIG", desc: "M-of-N signature check", category: "crypto" },
    { name: "OP_EQUAL", desc: "Compares top two items", category: "logic" },
    { name: "OP_EQUALVERIFY", desc: "Compare and verify", category: "logic" },
    { name: "OP_NUMEQUAL", desc: "Numeric equality", category: "logic" },
    { name: "OP_LESSTHAN", desc: "Less than comparison", category: "logic" },
    { name: "OP_GREATERTHAN", desc: "Greater than comparison", category: "logic" },
    { name: "OP_NOT", desc: "Boolean NOT", category: "logic" },
    { name: "OP_BOOLAND", desc: "Boolean AND", category: "logic" },
    { name: "OP_BOOLOR", desc: "Boolean OR", category: "logic" },
    { name: "OP_VERIFY", desc: "Fails if top is false", category: "flow" },
    { name: "OP_RETURN", desc: "Marks unspendable", category: "flow" },
    { name: "OP_IF", desc: "Conditional execution", category: "flow" },
    { name: "OP_NOTIF", desc: "Inverted conditional", category: "flow" },
    { name: "OP_ELSE", desc: "Else branch", category: "flow" },
    { name: "OP_ENDIF", desc: "End conditional", category: "flow" },
    { name: "OP_NOP", desc: "Does nothing", category: "flow" },
    { name: "OP_0", desc: "Pushes 0 (false)", category: "stack" },
    { name: "OP_1", desc: "Pushes 1 (true)", category: "stack" },
    { name: "OP_1NEGATE", desc: "Pushes -1", category: "stack" },
];

// Example scripts
const exampleScripts = [
    'OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG',
    'OP_HASH160 89abcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUAL',
    'OP_0 ab68025513c3dbd2f7b92a94e0581f5d50f654e7',
    'OP_RETURN 48656c6c6f20426974636f696e21',
    '2 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 2 OP_CHECKMULTISIG',
    '3 5 OP_ADD 8 OP_EQUAL'
];

let currentExampleIndex = 0;
let currentSteps = [];
let currentStepIndex = 0;

// Initialize
function init() {
    // Core functionality
    explainBtn.addEventListener('click', handleExplain);
    loadExampleBtn.addEventListener('click', handleLoadExample);

    // Keyboard shortcut
    scriptInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            handleExplain();
        }
    });

    // Step navigation
    prevStepBtn?.addEventListener('click', () => navigateStep(-1));
    nextStepBtn?.addEventListener('click', () => navigateStep(1));

    // Copy functionality
    copyResultBtn?.addEventListener('click', copyResults);

    // Example cards
    document.querySelectorAll('.example-card').forEach(card => {
        card.addEventListener('click', () => {
            const script = card.dataset.script;
            if (script) {
                scriptInput.value = script;
                document.getElementById('explainer').scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // Navigation smooth scroll
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            if (href.startsWith('#')) {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            }
        });
    });

    // Opcode search
    opcodeSearch?.addEventListener('input', filterOpcodes);

    // Opcode tabs
    document.querySelectorAll('.opcode-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.opcode-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            filterOpcodes();
        });
    });

    // Populate opcodes grid
    populateOpcodesGrid();

    // Parallax effect on planets
    document.addEventListener('mousemove', handleParallax);

    // Animate stats on scroll
    observeStats();
}

// Parallax effect for planets
function handleParallax(e) {
    const planets = document.querySelectorAll('.planet');
    const x = (e.clientX / window.innerWidth - 0.5) * 20;
    const y = (e.clientY / window.innerHeight - 0.5) * 20;

    planets.forEach((planet, index) => {
        const speed = (index % 3 + 1) * 0.5;
        planet.style.marginLeft = `${x * speed}px`;
        planet.style.marginTop = `${y * speed}px`;
    });
}

// Stats animation
function observeStats() {
    const statsValues = document.querySelectorAll('.stat-value');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateValue(entry.target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    statsValues.forEach(stat => observer.observe(stat));
}

function animateValue(element) {
    const target = parseInt(element.dataset.count);
    const suffix = element.textContent.includes('+') ? '+' :
        element.textContent.includes('%') ? '%' : '';

    let current = 0;
    const duration = 1500;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);

        current = Math.floor(target * eased);
        element.textContent = current + suffix;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// Opcodes Grid
function populateOpcodesGrid() {
    if (!opcodesGrid) return;

    opcodesGrid.innerHTML = '';

    opcodeData.forEach(opcode => {
        const item = document.createElement('div');
        item.className = 'opcode-item';
        item.dataset.category = opcode.category;
        item.dataset.name = opcode.name.toLowerCase();

        item.innerHTML = `
            <div class="opcode-name">${opcode.name}</div>
            <div class="opcode-desc">${opcode.desc}</div>
            <div class="opcode-category">${opcode.category}</div>
        `;

        opcodesGrid.appendChild(item);
    });
}

function filterOpcodes() {
    const searchTerm = opcodeSearch?.value.toLowerCase() || '';
    const activeTab = document.querySelector('.opcode-tab.active');
    const category = activeTab?.dataset.category || 'all';

    document.querySelectorAll('.opcode-item').forEach(item => {
        const name = item.dataset.name;
        const itemCategory = item.dataset.category;

        const matchesSearch = name.includes(searchTerm);
        const matchesCategory = category === 'all' || itemCategory === category;

        item.classList.toggle('hidden', !(matchesSearch && matchesCategory));
    });
}

// Handle explain
async function handleExplain() {
    const script = scriptInput.value.trim();

    if (!script) {
        showError('Please enter a Bitcoin Script to explain.');
        return;
    }

    hideAllStates();
    showLoading();

    try {
        const response = await fetch('/explain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ script: script }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Failed to explain script');
        }

        displayResults(data);

        // Track successful script explanation
        trackEvent('script_explained');
        updateLiveStats();

    } catch (error) {
        showError(error.message || 'An error occurred.');
    } finally {
        hideLoading();
    }
}

function handleLoadExample() {
    scriptInput.value = exampleScripts[currentExampleIndex];
    currentExampleIndex = (currentExampleIndex + 1) % exampleScripts.length;
    hideAllStates();
}

function displayResults(data) {
    scriptType.textContent = data.script_type;
    currentSteps = data.steps;
    currentStepIndex = 0;

    stepsContainer.innerHTML = '';
    data.steps.forEach((step, index) => {
        stepsContainer.appendChild(createStepElement(step, index));
    });

    updateStepCounter();
    summary.textContent = data.summary;
    results.classList.add('visible');

    setTimeout(() => {
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}

function createStepElement(step, index) {
    const div = document.createElement('div');
    div.className = 'step';

    const stackBefore = step.stack_before.length > 0
        ? step.stack_before.join(' | ')
        : '(empty)';
    const stackAfter = step.stack_after.length > 0
        ? step.stack_after.join(' | ')
        : '(empty)';

    div.innerHTML = `
        <div class="step-header">
            <span class="step-number">${index + 1}</span>
            <span class="step-opcode">${escapeHtml(step.opcode)}</span>
        </div>
        <div class="step-explanation">${escapeHtml(step.explanation)}</div>
        <div class="step-stacks">
            <div class="stack-display">
                <div class="stack-label">Stack Before</div>
                <div class="stack-items ${step.stack_before.length === 0 ? 'stack-empty' : ''}">
                    ${escapeHtml(stackBefore)}
                </div>
            </div>
            <div class="stack-display">
                <div class="stack-label">Stack After</div>
                <div class="stack-items ${step.stack_after.length === 0 ? 'stack-empty' : ''}">
                    ${escapeHtml(stackAfter)}
                </div>
            </div>
        </div>
    `;

    return div;
}

function navigateStep(direction) {
    const steps = stepsContainer.querySelectorAll('.step');
    if (steps.length === 0) return;

    steps[currentStepIndex]?.classList.remove('step-active');
    currentStepIndex = Math.max(0, Math.min(steps.length - 1, currentStepIndex + direction));
    steps[currentStepIndex]?.classList.add('step-active');
    steps[currentStepIndex]?.scrollIntoView({ behavior: 'smooth', block: 'center' });

    updateStepCounter();
}

function updateStepCounter() {
    if (stepCounter && currentSteps.length > 0) {
        stepCounter.textContent = `${currentStepIndex + 1}/${currentSteps.length}`;
    }
}

// State management
function showLoading() { loading.classList.add('visible'); }
function hideLoading() { loading.classList.remove('visible'); }
function showError(message) {
    errorText.textContent = message;
    errorMessage.classList.add('visible');
}
function hideAllStates() {
    loading.classList.remove('visible');
    errorMessage.classList.remove('visible');
    results.classList.remove('visible');
}

// Copy
async function copyResults() {
    const text = `Script Type: ${scriptType.textContent}\n\n${summary.textContent}`;

    try {
        await navigator.clipboard.writeText(text);
        copyResultBtn.innerHTML = '✓';
        copyResultBtn.style.color = '#10b981';
        setTimeout(() => {
            copyResultBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
            copyResultBtn.style.color = '';
        }, 2000);
    } catch (err) {
        console.error('Copy failed:', err);
    }
}

// Utility
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Active step style
const style = document.createElement('style');
style.textContent = `
    .step-active {
        border-color: var(--cosmos-purple) !important;
        box-shadow: 0 0 20px rgba(139, 92, 246, 0.2);
    }
`;
document.head.appendChild(style);

// Init
document.addEventListener('DOMContentLoaded', init);
