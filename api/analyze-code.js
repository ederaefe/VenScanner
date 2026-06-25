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

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return jsonResponse({
      status: 'unconfigured',
      message: 'Gemini API key not configured in environment variables.',
    }, 200);
  }

  try {
    const { code, language } = await req.json();
    if (!code || typeof code !== 'string') {
      return jsonResponse({ error: 'Code content must be a non-empty string' }, 400);
    }

    const langName = language || 'code';

    // Format the prompt and instruction
    const requestBody = {
      contents: [
        {
          parts: [
            {
              text: `Analyze the following ${langName} code:\n\n\`\`\`${langName}\n${code}\n\`\`\``
            }
          ]
        }
      ],
      systemInstruction: {
        parts: [
          {
            text: "You are an expert security code auditor. Analyze the provided code for vulnerabilities, bugs, memory safety issues (e.g. buffer overflows), injections (SQL, XSS, OS commands), weak cryptography, hardcoded secrets, or logic flaws. You MUST return your output as a JSON array of objects. Each object MUST contain the following keys exactly: 'severity' (must be 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'), 'line' (integer line number, 1-indexed, where the issue is found or starts), 'title' (short summary of the bug/vuln), 'description' (detailed reason), and 'remediation' (clear instruction/fix details)."
          }
        ]
      },
      generationConfig: {
        responseMimeType: "application/json"
      }
    };

    // Call Gemini API (using gemini-2.5-flash)
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      return jsonResponse({
        error: 'Gemini API query failed',
        details: errorText
      }, response.status);
    }

    const payload = await response.json();
    const rawText = payload?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!rawText) {
      return jsonResponse({ error: 'Empty response returned from AI model' }, 502);
    }

    // Try parsing the text locally to ensure it is valid JSON
    let auditReport;
    try {
      auditReport = JSON.parse(rawText.trim());
    } catch (parseErr) {
      // If parsing fails, wrap the text or return error
      return jsonResponse({
        error: 'Failed to parse AI output as JSON',
        rawOutput: rawText,
        message: parseErr.message
      }, 502);
    }

    return jsonResponse({
      status: 'success',
      report: auditReport
    }, 200);

  } catch (err) {
    return jsonResponse({ error: 'Internal server error', message: err.message }, 500);
  }
}
