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

async function findJobs(query) {
  // Fetch all open jobs and fuzzy-match by name — returns ALL matches
  const jobs = await gemGet('/ats/v0/jobs/?per_page=500&status=open');
  const q = query.toLowerCase().trim();
  const exact = jobs.filter(j => j.name.toLowerCase() === q);
  if (exact.length) return exact;
  return jobs.filter(j => j.name.toLowerCase().includes(q));
}

function jobLabel(job) {
  // Build a human-readable label including location if available
  const loc = job.location?.name || job.office?.name || job.offices?.[0]?.name;
  return loc ? `${job.name}  _(${loc})_` : job.name;
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
    const jobs = await findJobs(roleName);

    if (!jobs.length) {
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `❌  No open job found matching *"${roleName}"*.\nCheck the role name and try again.`
      });
    }

    // Multiple distinct reqs — ask the user to be more specific
    if (jobs.length > 1) {
      const list = jobs.map(j => `• ${jobLabel(j)}`).join('\n');
      return postBack(responseUrl, {
        response_type: 'ephemeral',
        text: `🔀  *${jobs.length} open roles* match *"${roleName}"*. Use a more specific name:\n\n${list}`
      });
    }

    const job = jobs[0];
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
