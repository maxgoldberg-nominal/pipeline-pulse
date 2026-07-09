const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.urlencoded({
  extended: true,
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));
app.use(express.json());

const GEM_API_KEY = process.env.GEM_API_KEY;
const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
const PORT = process.env.PORT || 3000;

const EXCLUDED_STAGES = ['application review', 'new applicant'];
const LATE_STAGE_KEYWORDS = ['on-site', 'onsite', 'on site', 'offer', 'reference', 'final', 'executive', 'panel', 'debrief'];

// ── Slack signature verification ─────────────────────────────────────────────
function verifySlack(req) {
  const ts = req.headers['x-slack-request-timestamp'];
  const sig = req.headers['x-slack-signature'];
  if (!ts || !sig) return false;
  if (Math.abs(Date.now() / 1000 - ts) > 300) return false;
  const base = `v0:${ts}:${req.rawBody}`;
  const expected = 'v0=' + crypto.createHmac('sha256', SLACK_SIGNING_SECRET).update(base).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig)); } catch { return false; }
}

// ── Gem API helpers ───────────────────────────────────────────────────────────
async function gemGet(path) {
  const res = await fetch(`https://api.gem.com${path}`, {
    headers: { 'X-API-Key': GEM_API_KEY, 'Content-Type': 'application/json' }
  });
  if (!res.ok) throw new Error(`Gem API ${res.status}: ${path}`);
  return res.json();
}

function jobLocation(job) {
  return job.location?.name || job.offices?.map(o => o.name).join(', ') || job.office?.name || '';
}

function normalizeDashes(str) {
  return str.replace(/[–—−]/g, '-');
}

async function findJobs(query) {
  const jobs = await gemGet('/ats/v0/jobs/?per_page=500&status=open');
  const q = normalizeDashes(query.toLowerCase().trim());
  const jn = j => normalizeDashes(j.name.toLowerCase());

  const exact = jobs.filter(j => jn(j) === q);
  if (exact.length) return exact;

  const nameInQuery = jobs.filter(j => q.includes(jn(j)));
  if (nameInQuery.length) {
    if (nameInQuery.length === 1) return nameInQuery;
    const narrow = nameInQuery.filter(j => {
      const loc = jobLocation(j).toLowerCase();
      return loc.split(/[\s,]+/).some(word => word.length > 2 && q.includes(word));
    });
    return narrow.length ? narrow : nameInQuery;
  }

  return jobs.filter(j => jn(j).includes(q));
}

async function getActiveApplications(jobId) {
  return gemGet(`/ats/v0/applications/?job_id=${jobId}&status=active&per_page=500`);
}

async function getAllApplications(jobId) {
  return gemGet(`/ats/v0/applications/?job_id=${jobId}&per_page=500`).catch(() => []);
}

async function getStageOrder(jobId) {
  const stages = await gemGet(`/ats/v0/jobs/${jobId}/stages`).catch(() => []);
  return new Map(stages.map(s => [s.name, s.priority ?? 999]));
}

function gemJobUrl(jobId) {
  return `https://www.gem.com/ats/jobs/${jobId}/candidates`;
}

function gemApplicationUrl(candidateId, applicationId) {
  try {
    const decoded = Buffer.from(candidateId, 'base64').toString('utf8');
    const match = decoded.match(/:(\d+)/);
    if (match) {
      const personId = Buffer.from(`Person:${match[1]}`).toString('base64');
      return `https://www.gem.com/candidate/${personId}/applications/${applicationId}`;
    }
  } catch {}
  return null;
}

async function getCandidate(candidateId) {
  try {
    const c = await gemGet(`/ats/v0/candidates/${candidateId}`);
    const name = c.name || [c.first_name, c.last_name].filter(Boolean).join(' ') || null;
    return name ? { name } : null;
  } catch {
    return null;
  }
}

// ── Slack Block Kit formatter ─────────────────────────────────────────────────
function buildBlocks(job, applications, stageOrder = new Map(), allStageCounts = new Map(), candidateNames = new Map()) {
  const stageMap = new Map();
  for (const app of applications) {
    const stage = app.current_stage?.name || 'Unknown';
    if (EXCLUDED_STAGES.includes(stage.toLowerCase())) continue;
    if (!stageMap.has(stage)) stageMap.set(stage, []);
    stageMap.get(stage).push(app);
  }

  const sortedStageMap = new Map(
    [...stageMap.entries()].sort(([a], [b]) => (stageOrder.get(a) ?? 999) - (stageOrder.get(b) ?? 999))
  );

  const total = applications.length;
  const maxCount = Math.max(...[...sortedStageMap.values()].map(a => a.length), 1);
  const stageEntries = [...sortedStageMap.entries()];

  const reqAgeDays = job.created_at
    ? Math.floor((Date.now() - new Date(job.created_at)) / 86_400_000)
    : null;

  const loc = jobLocation(job);
  const recruiters = job.hiring_team?.recruiters || [];
  const recruiterName = recruiters[0]?.name
    || [recruiters[0]?.first_name, recruiters[0]?.last_name].filter(Boolean).join(' ')
    || null;

  const metaParts = [
    `*${total} active candidate${total !== 1 ? 's' : ''}*`,
    loc ? `📍 ${loc}` : null,
    reqAgeDays !== null ? `📅 Open ${reqAgeDays}d` : null,
    recruiterName ? `👤 ${recruiterName}` : null,
  ].filter(Boolean);

  const jobUrl = gemJobUrl(job.id);
  if (jobUrl) metaParts.push(`<${jobUrl}|🔗 View in Gem>`);
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `📋  ${job.name}`, emoji: true } },
    { type: 'context', elements: [{ type: 'mrkdwn', text: metaParts.join('  ·  ') }] },
    { type: 'divider' }
  ];

  function candidateLink(app) {
    const c = candidateNames.get(app.candidate_id);
    if (!c) return null;
    const nameStr = c.url ? `<${c.url}|${c.name}>` : c.name;
    const days = app.last_activity_at
      ? Math.floor((Date.now() - new Date(app.last_activity_at)) / 86_400_000)
      : null;
    const stale = days !== null ? `  _${days}d ago_` : '';
    return nameStr + stale;
  }

  for (const [stage, apps] of stageEntries) {
    const count = apps.length;
    const filled = Math.round((count / maxCount) * 12);
    const bar = '█'.repeat(filled) + '░'.repeat(12 - filled);
    const isLateStage = LATE_STAGE_KEYWORDS.some(kw => stage.toLowerCase().includes(kw));
    const sortedApps = [...apps].sort((a, b) => new Date(b.last_activity_at) - new Date(a.last_activity_at));
    const showAll = isLateStage || count <= 5;
    const displayApps = showAll ? sortedApps : sortedApps.slice(0, 5);
    const names = displayApps.map(candidateLink).filter(Boolean);
    const overflow = count - displayApps.length;
    const overflowText = overflow > 0 && names.length > 0 ? `\n  _+${overflow} more_` : '';
    const nameList = names.length ? '\n' + names.map(n => `  › ${n}`).join('\n') + overflowText : '';
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `*${stage}*\n\`${bar}\`  *${count}*${nameList}` }
    });
  }

  // Source breakdown
  const sourceCounts = new Map();
  for (const app of applications) {
    const name = app.source?.public_name || app.source?.name || (typeof app.source === 'string' ? app.source : null);
    if (name) sourceCounts.set(name, (sourceCounts.get(name) || 0) + 1);
  }
  if (sourceCounts.size > 0) {
    const maxSource = Math.max(...sourceCounts.values());
    const sortedSources = [...sourceCounts.entries()].sort(([, a], [, b]) => b - a);
    const lines = sortedSources.map(([name, count]) => {
      const pct = Math.round((count / total) * 100);
      const filled = Math.round((count / maxSource) * 8);
      const bar = '█'.repeat(filled) + '░'.repeat(8 - filled);
      return `${name}  \`${bar}\`  ${count}  _${pct}%_`;
    });
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Source breakdown*\n${lines.join('\n')}` } });
  }

  blocks.push({ type: 'divider' });
  blocks.push({
    type: 'context',
    elements: [{ type: 'mrkdwn', text: `_Live from Gem ATS · ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}_` }]
  });

  return blocks;
}

// ── Shared pipeline fetch + post ──────────────────────────────────────────────
async function fetchAndPostPipeline(job, responseUrl) {
  const [applications, allApplications, stageOrder] = await Promise.all([
    getActiveApplications(job.id),
    getAllApplications(job.id),
    getStageOrder(job.id)
  ]);

  const allStageCounts = new Map();
  for (const app of allApplications) {
    const stage = app.current_stage?.name;
    if (stage) allStageCounts.set(stage, (allStageCounts.get(stage) || 0) + 1);
  }

  if (!applications.length) {
    return postBack(responseUrl, {
      response_type: 'ephemeral',
      text: `📭  No active candidates found for *${job.name}*.`
    });
  }

  const stageGroups = new Map();
  for (const app of applications) {
    const stage = app.current_stage?.name || 'Unknown';
    if (EXCLUDED_STAGES.includes(stage.toLowerCase())) continue;
    if (!stageGroups.has(stage)) stageGroups.set(stage, []);
    stageGroups.get(stage).push(app);
  }

  const needNames = new Map();
  for (const [stage, apps] of stageGroups) {
    const isLate = LATE_STAGE_KEYWORDS.some(kw => stage.toLowerCase().includes(kw));
    const sorted = [...apps].sort((a, b) => new Date(b.last_activity_at) - new Date(a.last_activity_at));
    const limit = (isLate || apps.length <= 5) ? sorted.length : 5;
    for (const a of sorted.slice(0, limit)) { if (a.candidate_id) needNames.set(a.candidate_id, a.id); }
  }

  const nameEntries = await Promise.all(
    [...needNames.entries()].map(async ([candidateId, appId]) => {
      const c = await getCandidate(candidateId);
      if (!c) return [candidateId, null];
      return [candidateId, { name: c.name, url: gemApplicationUrl(candidateId, appId) }];
    })
  );
  const candidateNames = new Map(nameEntries.filter(([, c]) => c));

  const blocks = buildBlocks(job, applications, stageOrder, allStageCounts, candidateNames);
  await postBack(responseUrl, { response_type: 'in_channel', blocks });
}

// ── Job picker dropdown ───────────────────────────────────────────────────────
async function showJobPicker(responseUrl, message) {
  const jobs = await gemGet('/ats/v0/jobs/?per_page=500&status=open');
  const sorted = [...jobs].sort((a, b) => a.name.localeCompare(b.name));
  const options = sorted.slice(0, 100).map(j => {
    const loc = jobLocation(j);
    const label = loc ? `${j.name}  —  ${loc}` : j.name;
    return {
      text: { type: 'plain_text', text: label.slice(0, 75), emoji: false },
      value: j.id
    };
  });
  await postBack(responseUrl, {
    response_type: 'ephemeral',
    blocks: [
      { type: 'section', text: { type: 'mrkdwn', text: message } },
      {
        type: 'actions',
        elements: [{
          type: 'static_select',
          placeholder: { type: 'plain_text', text: 'Search for a role...', emoji: false },
          options,
          action_id: 'select_job'
        }]
      }
    ]
  });
}

// ── Slash command: /pipeline ──────────────────────────────────────────────────
app.post('/slack/pipeline', async (req, res) => {
  if (SLACK_SIGNING_SECRET && !verifySlack(req)) return res.status(401).json({ error: 'Invalid signature' });

  const responseUrl = req.body.response_url;
  res.json({ response_type: 'ephemeral', text: '🔍  Loading open roles...' });

  try {
    await showJobPicker(responseUrl, 'Select a role to view its pipeline:');
  } catch (err) {
    console.error('Pipeline error:', err);
    await postBack(responseUrl, { response_type: 'ephemeral', text: `⚠️  Something went wrong. \`${err.message}\`` });
  }
});

// ── Interactive actions: job picker selection ─────────────────────────────────
app.post('/slack/actions', async (req, res) => {
  if (SLACK_SIGNING_SECRET && !verifySlack(req)) return res.status(401).json({ error: 'Invalid signature' });

  const payload = JSON.parse(req.body.payload);
  const action = payload.actions?.[0];
  const responseUrl = payload.response_url;

  if (action?.action_id !== 'select_job') return res.json({});

  res.json({}); // Ack within 3 seconds

  try {
    const jobId = action.selected_option.value;
    const allJobs = await gemGet('/ats/v0/jobs/?per_page=500&status=open');
    const job = allJobs.find(j => j.id === jobId);
    if (job) console.log('DEPT_FIELD:', JSON.stringify({ department: job.department, departments: job.departments }));
    if (!job) return postBack(responseUrl, { response_type: 'ephemeral', text: '❌  Job not found.' });
    await fetchAndPostPipeline(job, responseUrl);
  } catch (err) {
    console.error('Actions error:', err);
    await postBack(responseUrl, { response_type: 'ephemeral', text: `⚠️  Something went wrong. \`${err.message}\`` });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function postBack(url, body) {
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

app.get('/health', (req, res) => res.json({ ok: true, service: 'pipeline-pulse' }));
app.listen(PORT, () => console.log(`🚀  Pipeline Pulse running on port ${PORT}`));
