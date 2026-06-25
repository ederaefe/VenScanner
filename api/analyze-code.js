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

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return new Response(
      JSON.stringify({
        status: 'unconfigured',
        message: 'Gemini API key not configured in environment variables.',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }

  try {
    const { code, language } = await req.json();
    if (!code || typeof code !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Code content must be a non-empty string' }),
        { status: 400, headers: { 'content-type': 'application/json' } }
      );
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
      return new Response(
        JSON.stringify({
          error: 'Gemini API query failed',
          details: errorText
        }),
        { status: response.status, headers: { 'content-type': 'application/json' } }
      );
    }

    const payload = await response.json();
    const rawText = payload?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!rawText) {
      return new Response(
        JSON.stringify({ error: 'Empty response returned from AI model' }),
        { status: 502, headers: { 'content-type': 'application/json' } }
      );
    }

    // Try parsing the text locally to ensure it is valid JSON
    let auditReport;
    try {
      auditReport = JSON.parse(rawText.trim());
    } catch (parseErr) {
      // If parsing fails, wrap the text or return error
      return new Response(
        JSON.stringify({
          error: 'Failed to parse AI output as JSON',
          rawOutput: rawText,
          message: parseErr.message
        }),
        { status: 502, headers: { 'content-type': 'application/json' } }
      );
    }

    return new Response(
      JSON.stringify({
        status: 'success',
        report: auditReport
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
