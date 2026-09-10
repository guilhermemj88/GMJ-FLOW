'use strict';

// Correlation guardrail harness for the automatic mitigation execution table.
// Extracts the real correlation functions from frontend/index.html and runs
// them against the guardrail scenarios (A-F) plus the connector rules.

const fs = require('fs');
const vm = require('vm');
const path = require('path');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'frontend', 'index.html'), 'utf8');

const startMarker = '    function automaticMitigationExecutionKey(item = {}) {';
const endMarker = '\n    function renderBgpAnnouncements() {';
const start = html.indexOf(startMarker);
const end = html.indexOf(endMarker);
if (start < 0 || end < 0 || end < start) {
  console.error('markers not found');
  process.exit(2);
}
const code = html.slice(start, end);

const sandbox = {
  console,
  String,
  Number,
  Map,
  Object,
  Array,
  Date,
  escapeHtml: (value) => String(value),
  formatDateTime: (value) => (value ? String(value) : '-'),
  bgpAnnouncementIsOperationalActive: () => false,
  mitigationConnectorLink: () => '#connector',
  window: {},
  document: { getElementById: () => null },
  automaticMitigationExecutions: [],
  bgpAnnouncements: [],
};
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: 'correlation.js' });

const failures = [];
function check(condition, label) {
  if (condition) {
    console.log('OK: ' + label);
  } else {
    failures.push(label);
    console.log('FAIL: ' + label);
  }
}

const dims = {
  address_family: 'ipv4',
  destination: '193.233.54.0/32',
  protocol: 'udp',
  destination_port: '53',
};
const future = new Date(Date.now() + 3600 * 1000).toISOString();
const past = new Date(Date.now() - 3600 * 1000).toISOString();

function activeExecution(overrides = {}) {
  return Object.assign({
    id: 7001,
    anomaly_id: 7001,
    vector: 'DNS_SINGLE_FLOW_OUTBOUND',
    status: 'active',
    idempotency_key: 'k-active',
    connector_id: 2,
    action: 'discard',
    normalized_match: { ...dims },
  }, overrides);
}

function activeAnnouncement(overrides = {}) {
  return Object.assign({
    id: 8001,
    anomaly_id: 7001,
    status: 'advertised',
    mitigation_key: 'k-ann',
    connector_id: 2,
    action: 'discard',
    target_prefix: '193.233.54.0/32',
    dst_prefix: '193.233.54.0/32',
    protocol: 'udp',
    dst_port: '53',
    expires_at: future,
    attack_vector_name: 'DNS_SINGLE_FLOW_OUTBOUND',
  }, overrides);
}

function blockedItem(overrides = {}) {
  return Object.assign({
    id: 9000,
    anomaly_id: 9000,
    vector: 'DNS_QUERY_OUTBOUND_CLIENT',
    status: 'blocked',
    idempotency_key: '',
    connector_id: '',
    action: 'discard',
    normalized_match: { ...dims },
    error_code: 'candidate_not_automatic_eligible',
    error_message: 'candidate_not_automatic_eligible',
    policy_reason: '',
  }, overrides);
}

function stateFor(blocked, executions, announcements) {
  sandbox.automaticMitigationExecutions = executions;
  sandbox.bgpAnnouncements = announcements;
  const index = sandbox.automaticMitigationActiveIndex();
  return sandbox.automaticMitigationDisplayState(blocked, index);
}

// Connector compatibility rules (requirement 1).
check(
  sandbox.automaticMitigationConnectorCompatible('', 2) === true,
  'connector: empty vs 2 → compatible',
);
check(
  sandbox.automaticMitigationConnectorCompatible(2, 2) === true,
  'connector: 2 vs 2 → compatible',
);
check(
  sandbox.automaticMitigationConnectorCompatible(3, 2) === false,
  'connector: 3 vs 2 → NOT compatible (explicit conflict)',
);

// address_family is part of the mandatory dimensions (requirement 2).
check(
  sandbox.automaticMitigationCorrelationKey(activeExecution()).startsWith('ipv4|'),
  'correlation key includes address_family',
);

// A. blocked connector NULL + active connector 2 → ALREADY_MITIGATED.
const caseA = stateFor(blockedItem({ connector_id: '' }), [activeExecution()], []);
check(
  caseA.alreadyMitigated === true && caseA.code === 'ALREADY_MITIGATED',
  'A: blocked connector NULL + active connector 2 → ALREADY_MITIGATED',
);

// B. blocked connector 2 + active connector 2 → ALREADY_MITIGATED.
const caseB = stateFor(blockedItem({ connector_id: 2 }), [activeExecution()], []);
check(
  caseB.alreadyMitigated === true && caseB.code === 'ALREADY_MITIGATED',
  'B: blocked connector 2 + active connector 2 → ALREADY_MITIGATED',
);

// C. blocked connector 3 + active connector 2 → NOT correlated.
const caseC = stateFor(blockedItem({ connector_id: 3 }), [activeExecution()], []);
check(
  caseC.alreadyMitigated === false,
  'C: blocked connector 3 + active connector 2 → NOT correlated',
);

// D. same destination but different port → NOT correlated.
const caseD = stateFor(
  blockedItem({ normalized_match: { ...dims, destination_port: '54' } }),
  [activeExecution()],
  [],
);
check(
  caseD.alreadyMitigated === false,
  'D: same destination, different port → NOT correlated',
);

// E. same destination/port but different protocol → NOT correlated.
const caseE = stateFor(
  blockedItem({ normalized_match: { ...dims, protocol: 'tcp' } }),
  [activeExecution()],
  [],
);
check(
  caseE.alreadyMitigated === false,
  'E: same destination/port, different protocol → NOT correlated',
);

// F. equivalent mitigation withdrawn/expired → NOT ALREADY_MITIGATED.
const caseF1 = stateFor(
  blockedItem({ connector_id: '' }),
  [activeExecution({ status: 'withdrawn', idempotency_key: 'k-withdrawn' })],
  [],
);
check(
  caseF1.alreadyMitigated === false,
  'F1: equivalent execution withdrawn → NOT ALREADY_MITIGATED',
);

const caseF2 = stateFor(
  blockedItem({ connector_id: '' }),
  [],
  [activeAnnouncement({ status: 'expired', expires_at: past, mitigation_key: 'k-expired' })],
);
check(
  caseF2.alreadyMitigated === false,
  'F2: equivalent announcement expired → NOT ALREADY_MITIGATED',
);

const caseF3 = stateFor(
  blockedItem({ connector_id: '' }),
  [],
  [activeAnnouncement({ expires_at: past })],
);
check(
  caseF3.alreadyMitigated === false,
  'F3: announcement advertised but expires_at past → NOT ALREADY_MITIGATED',
);

// G. active advertised announcement with future expiry → ALREADY_MITIGATED.
const caseG = stateFor(blockedItem({ connector_id: '' }), [], [activeAnnouncement()]);
check(
  caseG.alreadyMitigated === true && caseG.responsible && caseG.responsible.announcement,
  'G: active advertised announcement (future expiry) → ALREADY_MITIGATED via announcement',
);

if (failures.length) {
  console.error('\nFAILURES:\n' + failures.join('\n'));
  process.exit(1);
}
console.log('\nAll checks passed.');
