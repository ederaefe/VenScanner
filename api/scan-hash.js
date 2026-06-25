export const config = {
  runtime: 'edge',
};

export default async function handler(req) {
  // Only accept POST requests
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'content-type': 'application/json' },
    });
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return new Response(
      JSON.stringify({
        status: 'unconfigured',
        message: 'VirusTotal API key not configured in environment variables.',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }

  try {
    const { hash } = await req.json();
    if (!hash || typeof hash !== 'string' || hash.length !== 64) {
      return new Response(
        JSON.stringify({ error: 'Invalid or missing SHA-256 hash' }),
        { status: 400, headers: { 'content-type': 'application/json' } }
      );
    }

    // Call VirusTotal API
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
      },
    });

    if (response.status === 404) {
      return new Response(
        JSON.stringify({
          status: 'unknown',
          message: 'File hash not found in the threat database.',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    }

    if (!response.ok) {
      const errorText = await response.text();
      return new Response(
        JSON.stringify({
          error: 'VirusTotal API query failed',
          details: errorText,
        }),
        { status: response.status, headers: { 'content-type': 'application/json' } }
      );
    }

    const payload = await response.json();
    const attributes = payload?.data?.attributes;

    if (!attributes) {
      return new Response(
        JSON.stringify({ error: 'Unexpected response layout from VirusTotal' }),
        { status: 502, headers: { 'content-type': 'application/json' } }
      );
    }

    const stats = attributes.last_analysis_stats || {};
    const reputation = attributes.reputation ?? 0;
    
    // We calculate a score and list detections
    return new Response(
      JSON.stringify({
        status: 'known',
        reputation: reputation,
        stats: {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'Internal server error', message: err.message }),
      { status: 500, headers: { 'content-type': 'application/json' } }
    );
  }
}
