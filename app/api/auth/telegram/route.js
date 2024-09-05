import crypto from 'crypto';

export async function GET(req) {
  const url = new URL(req.url);
  const query = Object.fromEntries(url.searchParams.entries());
  const { hash, id, username, first_name, last_name, photo_url, auth_date } = query;

  // Telegram authentication validation
  const secretKey = crypto.createHash('sha256').update(process.env.BOT_TOKEN).digest();
  const dataCheckString = Object.keys(query)
    .filter(key => key !== 'hash')
    .map(key => `${key}=${query[key]}`)
    .sort()
    .join('\n');

  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (hmac === hash) {
    // Authentication successful
    return new Response(JSON.stringify({ id, username, first_name, last_name, photo_url, auth_date }), {
      status: 200,
    });
  } else {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
}
