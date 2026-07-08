const express = require('express');
const crypto = require('crypto');

const app = express();

// Parse body & capture raw bytes for Slack signature verification
// The verify callback runs before parsing, giving us the exact bytes Slack signed
app.use(express.urlencoded({
  extended: true,
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));
app.use(express.json());

const GEM_API_KEY = process.env.GEM_API_KEY;
const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
const PORT = process.env.PORT || 3000;

// ── Slack signature verification ────────────────────────────────────────────
function verifySlack(req) {
  const ts = req.headers['x-slack-request-timestamp'];
  const sig = req.headers['x-slack-signature'];
  if (!ts || !sig) return false;
  if (Math.abs(Date.now() / 1000 - ts) > 300) return false; // replay guard
  const base = `v0:${ts}:${req.rawBody}`;
  const expected = 'v0=' + crypto.createHmac('sha256', SLACK_SIGNING_SECRET).update(base).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch {
    return false;
  }
}

// ── Gem API helpers ──────────────────────────────────────────────────────────
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

async function findJobs(query) {
  const jobs = await gemGet('/ats/v0/jobs/?per_page=500&status=open');
  const q = query.toLowerCase().trim();

  // 1. Exact name match
  const exact = jobs.filter(j => j.name.toLowerCase() === q);
  if (exact.length) return exact;

  // 2. Query contains the job name — handles "enterprise account executive los angeles"
  //    where the role name is a substring of what the user typed
  const nameInQuery = jobs.filter(j => q.includes(j.name.toLowerCase()));
  if (nameInQuery.length) {
    if (nameInQuery.length === 1) return nameInQuery;
    // Narrow by location words in the query
    const narrow = nameInQuery.filter(j => {
      const loc = jobLocation(j).toLowerCase();
      return loc.split(/[\s,]+/).some(word => word.length > 2 && q.includes(word));
    });
    return narrow.length ? narrow : nameInQuery;
  }

  // 3. Job name contains query — handles partial searches like "/pipeline baremetal"
  return jobs.filter(j => j.name.toLowerCase().includes(q));
}

async function getActiveApplications(jobId) {
  return gemGet(`/ats/v0/applications/?job_id=${jobId}&status=active&per_page=500`);
}

async function getAllApplications(jobId) {
  // Fetch all statuses for accurate funnel calculation
  return gemGet(`/ats/v0/applications/?job_id=${jobId}&per_page=500`).catch(() => []);
}

async function getStageOrder(jobId) {
  // Returns a Map of stage name → priority (lower = earlier in pipeline)
  const stages = await gemGet(`/ats/v0/jobs/${jobId}/stages`).catch(() => []);
  return new Map(stages.map(s => [s.name, s.priority ?? 999]));
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


// ── Slack Block Kit formatter ────────────────────────────────────────────────
function buildBlocks(job, applications, stageOrder = new Map(), allStageCounts = new Map(), candidateNames = new Map()) {
  const EXCLUDED_STAGES = ['application review', 'new applicant'];

  // Group by stage, skipping inbox/review stages
  const stageMap = new Map();
  for (const app of applications) {
    const stage = app.current_stage?.name || 'Unknown';
    if (EXCLUDED_STAGES.includes(stage.toLowerCase())) continue;
    if (!stageMap.has(stage)) stageMap.set(stage, []);
    stageMap.get(stage).push(app);
  }

  // Sort stages by pipeline priority; unknown stages go last
  const sortedStageMap = new Map(
    [...stageMap.entries()].sort(([a], [b]) => {
      const pa = stageOrder.get(a) ?? 999;
      const pb = stageOrder.get(b) ?? 999;
      return pa - pb;
    })
  );

  const total = applications.length;
  const maxCount = Math.max(...[...sortedStageMap.values()].map(a => a.length), 1);
  const stageEntries = [...sortedStageMap.entries()];

  // Req age
  const reqAgeDays = job.created_at
    ? Math.floor((Date.now() - new Date(job.created_at)) / 86_400_000)
    : null;
  const reqAgeText = reqAgeDays !== null
    ? `📅 Open ${reqAgeDays}d`
    : null;

  // Location
  const loc = jobLocation(job);
  const locText = loc ? `📍 ${loc}` : null;

  // Recruiter
  const r = applications[0]?.recruiter;
  const recruiterName = r?.name || [r?.first_name, r?.last_name].filter(Boolean).join(' ') || null;
  const recruiterText = recruiterName ? `👤 ${recruiterName}` : null;

  const metaParts = [
    `*${total} active candidate${total !== 1 ? 's' : ''}*`,
    locText,
    reqAgeText,
    recruiterText,
  ].filter(Boolean);

  const blocks = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `📋  ${job.name}`, emoji: true }
    },
    {
      type: 'context',
      elements: [{ type: 'mrkdwn', text: metaParts.join('  ·  ') }]
    },
    { type: 'divider' }
  ];

  // Stages where we show individual candidate names
  const LATE_STAGE_KEYWORDS = ['on-site', 'onsite', 'on site', 'offer', 'reference', 'final', 'executive', 'panel', 'debrief'];

  function candidateLink(app) {
    const c = candidateNames.get(app.candidate_id);
    if (!c) return null;
    const nameStr = c.url ? `<${c.url}|${c.name}>` : c.name;
    const days = app.last_activity_at
      ? Math.floor((Date.now() - new Date(app.last_activity_at)) / 86_400_000)
      : null;
    const stale = (days !== null && days > 5) ? `  _${days}d ago_` : '';
    return nameStr + stale;
  }

  for (let i = 0; i < stageEntries.length; i++) {
    const [stage, apps] = stageEntries[i];
    const count = apps.length;
    const filled = Math.round((count / maxCount) * 12);
    const bar = '█'.repeat(filled) + '░'.repeat(12 - filled);

    const funnelText = '';

    // Show names for late-stage candidates (on-site+) or any stage with ≤5 people
    const isLateStage = LATE_STAGE_KEYWORDS.some(kw => stage.toLowerCase().includes(kw));
    const names = (isLateStage || count <= 5)
      ? apps.map(candidateLink).filter(Boolean)
      : [];

    const nameList = names.length ? '\n' + names.map(n => `  › ${n}`).join('\n') : '';

    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*${stage}*${funnelText}\n\`${bar}\`  *${count}*${nameList}`
      }
    });
  }

  blocks.push({ type: 'divider' });
  blocks.push({
    type: 'context',
    elements: [{ type: 'mrkdwn', text: `_Live from Gem ATS · ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}_` }]
  });

  return blocks;
}

// ── Slash command handler ────────────────────────────────────────────────────
app.post('/slack/pipeline', async (req, res) => {
  // Verify signature (skip in dev if secret not set)
  if (SLACK_SIGNING_SECRET && !verifySlack(req)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const roleName = req.body.text?.trim();
  const responseUrl = req.body.response_url;

  if (!roleName) {
    return res.json({
      response_type: 'ephemeral',
      text: '*Usage:* `/pipeline [role name]`\n_Example: `/pipeline senior software engineer`_'
    });
  }

  // Acknowledge within 3 seconds, then do the work
  res.json({
    response_type: 'ephemeral',
    text: `🔍  Fetching pipeline for *${roleName}*...`
  });

  try {
    const jobs = await findJobs(roleName);

    if (!jobs.length) {
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `❌  No open job found matching *"${roleName}"*.\nCheck the role name and try again.`
      });
    }

    // Multiple reqs still ambiguous after location filtering — ask user to specify
    if (jobs.length > 1) {
      const lines = jobs.map(j => {
        const loc = jobLocation(j);
        const city = loc.split(',')[0].trim().toLowerCase();
        const hint = city ? `\`/pipeline ${jobs[0].name.toLowerCase()} ${city}\`` : '';
        return `• *${j.name}*${loc ? `  —  ${loc}` : ''}${hint ? `\n  → ${hint}` : ''}`;
      });
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `🔀  *${jobs.length} open reqs* match *"${roleName}"*. Add a location to your search:\n\n${lines.join('\n\n')}`
      });
    }

    const job = jobs[0];
    const [applications, allApplications, stageOrder] = await Promise.all([
      getActiveApplications(job.id),
      getAllApplications(job.id),
      getStageOrder(job.id)
    ]);

    // Build stage counts from ALL applications for accurate funnel %
    const allStageCounts = new Map();
    for (const app of allApplications) {
      const stage = app.current_stage?.name;
      if (stage) allStageCounts.set(stage, (allStageCounts.get(stage) || 0) + 1);
    }

    console.log('RECRUITER:', JSON.stringify(applications[0]?.recruiter));
    if (!applications.length) {
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `📭  No active candidates found for *${job.name}*.`
      });
    }

    // Pre-fetch candidate names for late stages and small stages
    const EXCLUDED_STAGES = ['application review', 'new applicant'];
    const LATE_STAGE_KEYWORDS = ['on-site', 'onsite', 'on site', 'offer', 'reference', 'final', 'executive', 'panel', 'debrief'];
    const stageGroups = new Map();
    for (const app of applications) {
      const stage = app.current_stage?.name || 'Unknown';
      if (EXCLUDED_STAGES.includes(stage.toLowerCase())) continue;
      if (!stageGroups.has(stage)) stageGroups.set(stage, []);
      stageGroups.get(stage).push(app);
    }
    const needNames = new Map(); // candidate_id → application_id
    for (const [stage, apps] of stageGroups) {
      const isLate = LATE_STAGE_KEYWORDS.some(kw => stage.toLowerCase().includes(kw));
      if (isLate || apps.length <= 5) {
        for (const a of apps) { if (a.candidate_id) needNames.set(a.candidate_id, a.id); }
      }
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

  } catch (err) {
    console.error('Pipeline error:', err);
    await postBack(responseUrl, {
      response_type: 'ephemeral',
      text: `⚠️  Something went wrong fetching the pipeline. Please try again.\n\`${err.message}\``
    });
  }
});

async function postBack(url, body) {
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, service: 'pipeline-pulse' }));

app.listen(PORT, () => console.log(`🚀  Pipeline Pulse running on port ${PORT}`));
