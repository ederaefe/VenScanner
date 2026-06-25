export const config = {
  runtime: 'edge',
};

const SECURITY_HEADERS = {
  'content-type': 'application/json',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; sandbox;"
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: SECURITY_HEADERS
  });
}

export default async function handler(req) {
  // Only accept POST requests
  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return jsonResponse({
      status: 'unconfigured',
      message: 'VirusTotal API key not configured in environment variables.'
    }, 200);
  }

  try {
    const { url } = await req.json();
    if (!url || typeof url !== 'string' || !url.startsWith('http')) {
      return jsonResponse({ error: 'Invalid or missing target URL (must start with http/https)' }, 400);
    }

    const cleanUrl = url.trim();

    // Standard base64 encoding without padding (as required by VirusTotal API v3)
    let base64Url;
    try {
      base64Url = btoa(cleanUrl).replace(/=/g, '');
    } catch (encodeErr) {
      // Handle potential unicode character encoding errors in btoa
      const utf8Bytes = new TextEncoder().encode(cleanUrl);
      let binary = '';
      const len = utf8Bytes.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(utf8Bytes[i]);
      }
      base64Url = btoa(binary).replace(/=/g, '');
    }

    // Call VirusTotal API URL endpoint
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${base64Url}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
      },
    });

    if (response.status === 404) {
      return jsonResponse({
        status: 'unknown',
        message: 'URL not found in threat database.'
      }, 200);
    }

    if (!response.ok) {
      const errorText = await response.text();
      return jsonResponse({
        error: 'VirusTotal API query failed',
        details: errorText
      }, response.status);
    }

    const payload = await response.json();
    const attributes = payload?.data?.attributes;

    if (!attributes) {
      return jsonResponse({ error: 'Unexpected response layout from VirusTotal' }, 502);
    }

    const stats = attributes.last_analysis_stats || {};
    const reputation = attributes.reputation ?? 0;
    
    return jsonResponse({
      status: 'known',
      reputation: reputation,
      stats: {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
      }
    }, 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal server error', message: err.message }, 500);
  }
}
