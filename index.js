const express = require('express');
const crypto = require('crypto');

const app = express();

// Capture raw body for Slack signature verification
app.use((req, res, next) => {
  let data = '';
  req.on('data', chunk => (data += chunk));
  req.on('end', () => {
    req.rawBody = data;
    next();
  });
});
app.use(express.urlencoded({ extended: true }));
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

async function findJob(query) {
  // Fetch all open jobs and fuzzy-match by name
  const jobs = await gemGet('/ats/v0/jobs/?per_page=500&status=open');
  const q = query.toLowerCase().trim();
  // Exact match first, then partial
  return (
    jobs.find(j => j.name.toLowerCase() === q) ||
    jobs.find(j => j.name.toLowerCase().includes(q))
  );
}

async function getActiveApplications(jobId) {
  return gemGet(`/ats/v0/applications/?job_id=${jobId}&status=active&per_page=500`);
}

async function getPendingScorecards(jobId) {
  // Find interviews that happened but have no submitted scorecard
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // >24hrs ago
  const interviews = await gemGet(
    `/ats/v0/scheduled_interviews/?ends_before=${cutoff}&application_id=` +
    `&per_page=500`
  ).catch(() => []);
  // Count interviewers with no scorecard_id
  let pending = 0;
  for (const interview of interviews) {
    for (const interviewer of interview.interviewers || []) {
      if (!interviewer.scorecard_id) pending++;
    }
  }
  return pending;
}

// ── Slack Block Kit formatter ────────────────────────────────────────────────
function buildBlocks(job, applications) {
  // Group by stage, preserving insertion order (stages appear as encountered)
  const stageMap = new Map();
  for (const app of applications) {
    const stage = app.current_stage?.name || 'Unknown';
    if (!stageMap.has(stage)) stageMap.set(stage, []);
    stageMap.get(stage).push(app);
  }

  const total = applications.length;
  const maxCount = Math.max(...[...stageMap.values()].map(a => a.length), 1);

  const blocks = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `📋  ${job.name}`, emoji: true }
    },
    {
      type: 'context',
      elements: [{
        type: 'mrkdwn',
        text: `*${total} active candidate${total !== 1 ? 's' : ''}*  ·  ${stageMap.size} stage${stageMap.size !== 1 ? 's' : ''}`
      }]
    },
    { type: 'divider' }
  ];

  for (const [stage, apps] of stageMap) {
    const count = apps.length;
    // Bar: scale to max 12 blocks
    const filled = Math.round((count / maxCount) * 12);
    const bar = '█'.repeat(filled) + '░'.repeat(12 - filled);
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*${stage}*\n\`${bar}\`  *${count}*`
      }
    });
  }

  blocks.push({ type: 'divider' });
  blocks.push({
    type: 'context',
    elements: [{
      type: 'mrkdwn',
      text: `_Live from Gem ATS · ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}_`
    }]
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
    const job = await findJob(roleName);

    if (!job) {
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `❌  No open job found matching *"${roleName}"*.\nCheck the role name and try again.`
      });
    }

    const applications = await getActiveApplications(job.id);

    if (!applications.length) {
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `📭  No active candidates found for *${job.name}*.`
      });
    }

    const blocks = buildBlocks(job, applications);
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
