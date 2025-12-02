export interface Env {
  VIDEOS_BUCKET: R2Bucket;
  GITHUB_TOKEN: string;
  JOB_SECRET: string;
  GITHUB_REPO: string;
  GITHUB_OWNER: string;
}

// Download job status types
interface DownloadJob {
  job_id: string;
  video_url: string;
  format: string;
  audio_only: boolean;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  created_at: string;
  updated_at: string;
  title?: string;
  filename?: string;
  filesize?: number;
  r2_path?: string;
  error?: string;
}

const XOR_KEY = "super_secret_proxy_key";
const PARAM_URL = "__url";
const PARAM_LITE = "__lite";
const PARAM_TITLE = "__title";
const PARAM_COOKIE = "__proxy_session";
const PARAM_TITLE_COOKIE = "__proxy_title";
const PARAM_LITE_COOKIE = "__proxy_lite";
const PARAM_UA_MOBILE = "__ua_mobile";
const PARAM_UA_COOKIE = "__proxy_ua_mobile";
const PARAM_NOIMG = "__noimg";
const PARAM_NOIMG_COOKIE = "__proxy_noimg";
const PARAM_SEARCH = "__search";
const PARAM_YTDL = "__m";
const PARAM_COBALT = "__c";
const PARAM_AUTH = "__proxy_auth";
const PARAM_API = "api";
const AUTH_USER = "shogo";
const AUTH_PASS = "20070713";

// Helper to parse cookies
function parseCookies(cookieHeader: string | null): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    if (!value) return;
    list[name] = decodeURIComponent(value);
  });
  return list;
}

// XOR Obfuscation Logic
function xorProcess(input: string): string {
  let result = '';
  for (let i = 0; i < input.length; i++) {
    result += String.fromCharCode(input.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
  }
  return result;
}

function obfuscate(url: string): string {
  // XOR then Hex encode to be URL safe
  const xored = xorProcess(url);
  return Array.from(xored).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function deobfuscate(hex: string): string {
  // Hex decode then XOR
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return xorProcess(str);
}

class AttributeRewriter {
  attributeName: string;
  baseUrl: string;

  constructor(attributeName: string, baseUrl: string) {
    this.attributeName = attributeName;
    this.baseUrl = baseUrl;
  }

  element(element: Element) {
    const attribute = element.getAttribute(this.attributeName);
    if (attribute && !attribute.startsWith('data:') && !attribute.startsWith('#')) {
      try {
        const absoluteUrl = new URL(attribute, this.baseUrl).toString();
        const obfuscated = obfuscate(absoluteUrl);
        element.setAttribute(this.attributeName, `/?${PARAM_URL}=${obfuscated}`);
      } catch (e) {
        // Ignore invalid URLs
      }
    }
  }
}

class SrcSetRewriter {
  baseUrl: string;
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }
  element(element: Element) {
    const srcset = element.getAttribute('srcset');
    if (srcset) {
      try {
        const newSrcset = srcset.split(',').map(part => {
          const trimmed = part.trim();
          const [url, ...descriptors] = trimmed.split(/\s+/);
          if (url && !url.startsWith('data:')) {
             const absoluteUrl = new URL(url, this.baseUrl).toString();
             const obfuscated = obfuscate(absoluteUrl);
             return `/?${PARAM_URL}=${obfuscated} ${descriptors.join(' ')}`;
          }
          return part;
        }).join(', ');
        element.setAttribute('srcset', newSrcset);
      } catch (e) {}
    }
  }
}

class MetaRefreshRewriter {
  baseUrl: string;
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }
  element(element: Element) {
    const content = element.getAttribute('content');
    if (content) {
      try {
        // content="0; url=http://example.com"
        const parts = content.split(';');
        let urlPart = parts.find(p => p.trim().toLowerCase().startsWith('url='));
        if (urlPart) {
          const url = urlPart.trim().substring(4); // remove 'url='
          // Handle quotes if present
          const cleanUrl = url.replace(/^['"]|['"]$/g, '');
          
          const absoluteUrl = new URL(cleanUrl, this.baseUrl).toString();
          const obfuscated = obfuscate(absoluteUrl);
          
          // Reconstruct content
          const newContent = parts.map(p => {
            if (p.trim().toLowerCase().startsWith('url=')) {
              return `url=/?${PARAM_URL}=${obfuscated}`;
            }
            return p;
          }).join(';');
          
          element.setAttribute('content', newContent);
        }
      } catch (e) {}
    }
  }
}

class FormRewriter {
  baseUrl: string;
  isLite: boolean;
  customTitle: string | null;

  constructor(baseUrl: string, isLite: boolean, customTitle: string | null) {
    this.baseUrl = baseUrl;
    this.isLite = isLite;
    this.customTitle = customTitle;
  }

  element(element: Element) {
    const method = element.getAttribute('method')?.toUpperCase() || 'GET';
    const action = element.getAttribute('action');
    
    // If action is empty, it submits to current URL (the proxy URL), which is fine but might need params
    // If action is present, we need to rewrite it
    
    let targetActionUrl = this.baseUrl; // Default to current page if action is missing
    if (action) {
      try {
        targetActionUrl = new URL(action, this.baseUrl).toString();
      } catch (e) {
        // Invalid action URL, ignore
        return;
      }
    }

    const obfuscated = obfuscate(targetActionUrl);

    if (method === 'GET') {
      // GET forms clear query params in action, so use hidden inputs
      element.setAttribute('action', '/');
      
      // We need to ensure we don't duplicate hidden inputs if they already exist (though unlikely with this rewriter)
      // Append hidden inputs for proxy state
      let hiddenInputs = `<input type="hidden" name="${PARAM_URL}" value="${obfuscated}">`;
      if (this.isLite) {
        hiddenInputs += `<input type="hidden" name="${PARAM_LITE}" value="1">`;
      }
      if (this.customTitle) {
        hiddenInputs += `<input type="hidden" name="${PARAM_TITLE}" value="${this.customTitle}">`;
      }
      element.append(hiddenInputs, { html: true });
    } else {
      // POST forms can keep query params in action
      let newAction = `/?${PARAM_URL}=${obfuscated}`;
      if (this.isLite) newAction += `&${PARAM_LITE}=1`;
      if (this.customTitle) newAction += `&${PARAM_TITLE}=${encodeURIComponent(this.customTitle)}`;
      element.setAttribute('action', newAction);
    }
  }
}

class AdBlockRewriter {
  element(element: Element) {
    const src = element.getAttribute('src');
    const href = element.getAttribute('href');
    const adDomains = [
      'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
      'adnxs.com', 'criteo.com', 'rubiconproject.com', 'outbrain.com',
      'taboola.com', 'popin.cc', 'popin.popin.cc', 'microad.jp',
      'ads.yahoo.com', 'yimg.jp/ad', 'i-mobile.co.jp'
    ];
    
    const check = (url: string | null) => {
        if (!url) return false;
        return adDomains.some(domain => url.includes(domain));
    };

    if (check(src) || check(href)) {
        element.remove();
    }
  }
}

// --- Download API Handler (extracted to bypass auth) ---
async function handleDownloadAPI(request: Request, env: Env, url: URL, pathname: string): Promise<Response> {
  function genJobId() {
    const a = crypto.getRandomValues(new Uint8Array(6));
    return Date.now().toString(36) + '-' + Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function writeMeta(jobId: string, meta: any) {
    try {
      await env.VIDEOS_BUCKET.put(`videos/${jobId}/meta.json`, JSON.stringify(meta), {
        httpMetadata: { contentType: 'application/json; charset=utf-8' }
      });
    } catch (e) {
      console.log('[DownloadAPI] Error writing meta to R2:', e);
    }
  }

  // POST /api/download/request
  if (pathname === '/api/download/request' && request.method === 'POST') {
    try {
      const body = await request.json().catch(() => null) as any;
      if (!body || !body.url) return new Response(JSON.stringify({ error: 'url required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

      const jobId = genJobId();
      const meta: DownloadJob = {
        job_id: jobId,
        video_url: body.url,
        format: body.format || body.f || 'best',
        audio_only: !!body.audio_only,
        status: 'pending',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      // Save initial meta
      await writeMeta(jobId, meta);

      // Dispatch GitHub Actions via repository_dispatch
      try {
        if (env.GITHUB_TOKEN && env.GITHUB_OWNER && env.GITHUB_REPO) {
          const dispatchUrl = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/dispatches`;
          const payload = {
            event_type: 'yt_download',
            client_payload: {
              job_id: jobId,
              url: body.url,
              format: meta.format,
              callback_url: body.callback_url || `${new URL(request.url).origin}/api/download/callback`
            }
          };
          const resp = await fetch(dispatchUrl, {
            method: 'POST',
            headers: {
              'Authorization': `token ${env.GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github+json',
              'Content-Type': 'application/json',
              'User-Agent': 'CloudflareWorker'
            },
            body: JSON.stringify(payload)
          });
          console.log('[DownloadAPI] GitHub dispatch response:', resp.status);
          // Update meta to processing
          meta.status = resp.ok ? 'processing' : 'pending';
          meta.updated_at = new Date().toISOString();
          await writeMeta(jobId, meta);
        } else {
          console.log('[DownloadAPI] GITHUB_TOKEN or GITHUB_REPO not configured in env. Skipping dispatch.');
        }
      } catch (e: any) {
        console.log('[DownloadAPI] Dispatch error:', e.message || e);
      }

      return new Response(JSON.stringify({ job_id: jobId }), { status: 202, headers: { 'Content-Type': 'application/json' } });
    } catch (e: any) {
      console.log('[DownloadAPI] Request error:', e.message || e);
      return new Response(JSON.stringify({ error: e.message || String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // POST /api/download/callback
  if (pathname === '/api/download/callback' && request.method === 'POST') {
    const incomingSecret = request.headers.get('X-Job-Secret') || request.headers.get('x-job-secret');
    if (!env.JOB_SECRET || !incomingSecret || incomingSecret !== env.JOB_SECRET) {
      return new Response(JSON.stringify({ error: 'invalid secret' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }

    try {
      const body = await request.json().catch(() => null) as any;
      if (!body || !body.job_id) return new Response(JSON.stringify({ error: 'job_id required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      const jobId = body.job_id;

      // Read existing meta if exists
      let metaObj: any = { job_id: jobId };
      try {
        const existing = await env.VIDEOS_BUCKET.get(`videos/${jobId}/meta.json`);
        if (existing && existing.body) {
          const txt = await existing.text();
          metaObj = JSON.parse(txt || '{}');
        }
      } catch (e) { /* ignore */ }

      metaObj.updated_at = new Date().toISOString();
      if (body.status) metaObj.status = body.status;
      if (body.filename) metaObj.filename = body.filename;
      if (body.filesize) metaObj.filesize = body.filesize;
      if (body.title) metaObj.title = body.title;
      if (body.r2_path) metaObj.r2_path = body.r2_path;
      if (body.error) metaObj.error = body.error;

      await writeMeta(jobId, metaObj);

      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e: any) {
      console.log('[DownloadAPI] Callback processing error:', e.message || e);
      return new Response(JSON.stringify({ error: e.message || String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // GET /api/download/status?job_id=... or /api/download/status/:jobId
  if (pathname.startsWith('/api/download/status') && request.method === 'GET') {
    let jobId = url.searchParams.get('job_id') || url.searchParams.get('jobId') || '';
    if (!jobId) {
      const parts = pathname.split('/').filter(Boolean);
      if (parts.length >= 4) jobId = parts[3];
    }
    if (!jobId) return new Response(JSON.stringify({ error: 'job_id required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

    try {
      const obj = await env.VIDEOS_BUCKET.get(`videos/${jobId}/meta.json`);
      if (!obj || !obj.body) return new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      const txt = await obj.text();
      return new Response(txt, { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e: any) {
      return new Response(JSON.stringify({ error: e.message || String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // GET /api/download/list -> list job meta entries
  if (pathname === '/api/download/list' && request.method === 'GET') {
    try {
      const list = await env.VIDEOS_BUCKET.list({ prefix: 'videos/' });
      const jobIds = new Set<string>();
      const objects = list.objects || [];
      for (const item of objects) {
        if (item && item.key) {
          const parts = item.key.split('/');
          if (parts.length >= 2 && parts[1]) jobIds.add(parts[1]);
        }
      }
      const results: any[] = [];
      for (const id of jobIds) {
        try {
          const obj = await env.VIDEOS_BUCKET.get(`videos/${id}/meta.json`);
          if (obj && obj.body) {
            const txt = await obj.text();
            results.push(JSON.parse(txt || '{}'));
          }
        } catch (e) { /* ignore individual errors */ }
      }
      return new Response(JSON.stringify({ jobs: results }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e: any) {
      console.log('[DownloadAPI] List error:', e.message || e);
      return new Response(JSON.stringify({ error: e.message || String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // Default: not found for /api/download/* paths
  return new Response(JSON.stringify({ error: 'endpoint not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname || '/';

    // --- API endpoints that bypass authentication ---
    // /api/download/* endpoints need to be accessible without login
    if (pathname.startsWith('/api/download/')) {
      return handleDownloadAPI(request, env, url, pathname);
    }
    
    // /video/* endpoint to serve R2 files (also bypasses auth)
    if (pathname.startsWith('/video/') && request.method === 'GET') {
      const parts = pathname.split('/').filter(Boolean);
      if (parts.length < 3) return new Response('Bad Request', { status: 400 });
      const jobId = parts[1];
      const filename = parts.slice(2).join('/');
      try {
        const obj = await env.VIDEOS_BUCKET.get(`videos/${jobId}/${filename}`);
        if (!obj || !obj.body) return new Response('Not Found', { status: 404 });
        const headers = new Headers();
        if (obj.httpMetadata && obj.httpMetadata.contentType) headers.set('Content-Type', obj.httpMetadata.contentType);
        if (obj.httpMetadata && obj.httpMetadata.contentDisposition) headers.set('Content-Disposition', obj.httpMetadata.contentDisposition as string);
        return new Response(obj.body, { status: 200, headers });
      } catch (e: any) {
        console.log('[DownloadAPI] Error serving R2 object:', e.message || e);
        return new Response('Internal Error', { status: 500 });
      }
    }
    
    // --- Authentication Logic ---
    const cookies = parseCookies(request.headers.get('Cookie'));
    const isAuth = cookies[PARAM_AUTH] === 'true';

    if (!isAuth) {
      // Check for Login POST
      if (request.method === 'POST' && url.pathname === '/login') {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');
        if (username === AUTH_USER && password === AUTH_PASS) {
          const headers = new Headers();
          headers.append('Set-Cookie', `${PARAM_AUTH}=true; Path=/; HttpOnly; SameSite=Lax`);
          headers.append('Location', '/');
          return new Response(null, { status: 302, headers });
        } else {
           return new Response('Incorrect Username or Password', { status: 403 });
        }
      }

      // Show Login Page
      const loginHtml = `
      <!DOCTYPE html>
      <html lang="ja">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>東進学力ＰＯＳ</title>
        <style>
            body { font-family: "Hiragino Kaku Gothic ProN", Meiryo, sans-serif; margin: 0; background: #fff; color: #333; }
            .wrapper { width: 100%; max-width: 960px; margin: 0 auto; }
            .pos-header { padding: 10px 20px; border-bottom: 3px solid #009944; display: flex; align-items: center; justify-content: space-between; }
            .pos-header-logo { font-size: 22px; font-weight: bold; color: #009944; display: flex; align-items: center; gap: 10px; }
            .pos-body { padding: 60px 20px; background: #f9f9f9; min-height: 500px; display: flex; justify-content: center; align-items: flex-start; }
            .pos-body-login-box { background: #fff; padding: 40px; border: 1px solid #ddd; width: 100%; max-width: 450px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
            .pos-body-login-account, .pos-body-login-password { margin-bottom: 20px; }
            .pos-body-login-account span, .pos-body-login-password span { display: block; font-weight: bold; margin-bottom: 8px; font-size: 14px; color: #333; }
            input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 3px; box-sizing: border-box; font-size: 16px; }
            .pos-body-login-button { text-align: center; margin-top: 30px; }
            button { background: #009944; color: #fff; border: none; padding: 12px 50px; font-size: 16px; font-weight: bold; cursor: pointer; border-radius: 4px; transition: background 0.2s; }
            button:hover { background: #007a37; }
            .pos-footer { text-align: center; padding: 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; background: #fff; }
            .notice { font-size: 12px; color: #666; margin-top: 5px; line-height: 1.4; }
            a { color: #009944; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="pos-header">
            <div class="pos-header-logo">
              <span>東進学力ＰＯＳ</span>
            </div>
            <div style="font-size: 12px; text-align: right;">
              <a href="#">初回ログインの手順</a> | <a href="#">FAQ</a> | <a href="#">動作環境</a>
            </div>
          </div>
          <div class="pos-body">
            <div class="pos-body-login-box">
              <div style="text-align: center; margin-bottom: 20px; color: #009944; font-weight: bold; font-size: 18px;">ログイン</div>
              <form method="POST" action="/login">
                <div class="pos-body-login-account">
                  <span>ログインID</span>
                  <input name="username" type="text" tabindex="1" placeholder="" required>
                </div>
                <div class="notice">
                  ※生徒・ご父母のどちらのアカウントでもログインできます。<br>
                  ※ご父母用学力POSへログインする場合は、生徒用ログインIDの先頭に「P」をつけて下さい。
                </div>
                <div class="pos-body-login-password" style="margin-top: 20px;">
                  <span>パスワード</span>
                  <input name="password" type="password" tabindex="2" placeholder="" required>
                </div>
                <div class="notice" style="text-align: right;">
                  <a href="#">パスワードを忘れた方はこちら</a>
                </div>
                <div class="pos-body-login-button">
                  <button type="submit">ログイン</button>
                </div>
              </form>
              <div class="notice" style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px;">
                パスワードは、皆さんの学習情報・個人情報を守る極めて重要な情報です。他人に教えないよう管理をお願いします。
              </div>
            </div>
          </div>
          <div class="pos-footer">
            Copyright (C) Nagase Brothers Inc.
          </div>
        </div>
      </body>
      </html>
      `;
      return new Response(loginHtml, { headers: { 'Content-Type': 'text/html' } });
    }
    // ----------------------------


    let queryUrl = url.searchParams.get(PARAM_URL);
    
    // Lite Mode Logic: Param > Cookie > Default (false)
    let isLite = url.searchParams.get(PARAM_LITE) === '1';
    if (!url.searchParams.has(PARAM_LITE) && cookies[PARAM_LITE_COOKIE] === '1') {
        isLite = true;
    }

    // UA Logic: Param > Cookie > Default (false/PC)
    let isMobile = url.searchParams.get(PARAM_UA_MOBILE) === '1';
    if (!url.searchParams.has(PARAM_UA_MOBILE) && cookies[PARAM_UA_COOKIE] === '1') {
        isMobile = true;
    }

    // No Image Logic: Param > Cookie > Default (false)
    let noImg = url.searchParams.get(PARAM_NOIMG) === '1';
    if (!url.searchParams.has(PARAM_NOIMG) && cookies[PARAM_NOIMG_COOKIE] === '1') {
        noImg = true;
    }

    // Title Logic: Param > Cookie > Default
    let customTitle = url.searchParams.get(PARAM_TITLE);
    if (!customTitle && cookies[PARAM_TITLE_COOKIE]) {
        customTitle = cookies[PARAM_TITLE_COOKIE];
    }
    if (!customTitle) customTitle = "東進学力ＰＯＳ";

    // Check for YouTube download request (obfuscated)
    const ytdlQueryObf = url.searchParams.get(PARAM_YTDL);
    const formatOption = url.searchParams.get('f') || url.searchParams.get('format') || 'all';
    const apiOption = url.searchParams.get(PARAM_API) || 'auto'; // auto, piped, invidious, vevioz, cobalt, y2mate, allscan
    if (ytdlQueryObf) {
        // Deobfuscate the input
        const ytdlQuery = deobfuscate(ytdlQueryObf);
        console.log('[YTDL-Worker] Received obfuscated request, decoded:', ytdlQuery, 'Format:', formatOption);
        
        // Extract Video ID from various YouTube URL formats
        let videoId = ytdlQuery.trim();
        let fullYoutubeUrl = ytdlQuery.trim();
        
        // Handle full YouTube URLs
        const ytRegex = /(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/;
        const match = ytdlQuery.match(ytRegex);
        if (match) {
            videoId = match[1];
            fullYoutubeUrl = `https://www.youtube.com/watch?v=${videoId}`;
            console.log('[YTDL-Worker] Extracted Video ID from URL:', videoId);
        } else if (/^[a-zA-Z0-9_-]{11}$/.test(videoId)) {
            fullYoutubeUrl = `https://www.youtube.com/watch?v=${videoId}`;
        } else {
            console.log('[YTDL-Worker] Invalid Video ID format:', videoId);
            return new Response('Invalid YouTube URL or Video ID', { status: 400 });
        }
        
        console.log('[YTDL-Worker] Video ID:', videoId);
        console.log('[YTDL-Worker] Full URL:', fullYoutubeUrl);
        
        // For allscan mode, collect results from ALL APIs
        const isAllScan = apiOption === 'allscan';
        
        interface CollectedFormat {
            url: string;
            container: string;
            quality: string;
            type: 'audio' | 'video';
            bitrate?: string;
            size?: string;
            source: string; // Which API provided this format
        }
        
        const allAudioFormats: CollectedFormat[] = [];
        const allVideoFormats: CollectedFormat[] = [];
        let videoTitle = 'Unknown Title';
        let videoAuthor = 'Unknown';
        let videoDuration = '0:00';
        let videoThumbnail = `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`;
        const successfulApis: string[] = [];
        
        let downloadData: any = null;
        let lastError: string = '';
        const allErrors: string[] = [];
        let successInstance = '';
        
        console.log('[YTDL-Worker] API Option:', apiOption, 'AllScan:', isAllScan);
        
        // ===== API 1: Piped API instances (15 instances) =====
        const pipedInstances = [
            'https://api.piped.private.coffee',
            'https://pipedapi.darkness.services',
            'https://pipedapi.ducks.party',
            'https://pipedapi.ngn.tf',
            'https://api.piped.projectsegfau.lt',
            'https://pipedapi.moomoo.me',
            'https://pipedapi.leptons.xyz',
            'https://pipedapi.kavin.rocks',
            'https://pipedapi.aeong.one',
            'https://pipedapi.adminforge.de',
            'https://pipedapi.r4fo.com',
            'https://api.piped.yt',
            'https://pipedapi.in.projectsegfau.lt',
            'https://piped-api.privacy.com.de',
            'https://api.piped.privacydev.net'
        ];
        
        // Try Piped if auto or piped or allscan selected
        if (apiOption === 'auto' || apiOption === 'piped' || isAllScan) {
            console.log('[YTDL-Worker] Trying Piped API instances...');
        
        for (const instance of pipedInstances) {
            if (downloadData && !isAllScan) break;
            const apiUrl = `${instance}/streams/${videoId}`;
            console.log('[YTDL-Worker] Trying Piped:', apiUrl);
            
            try {
                const resp = await fetch(apiUrl, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/json'
                    }
                });
                
                console.log('[YTDL-Worker] Piped', instance, '-> Status:', resp.status);
                
                if (resp.ok) {
                    const data = await resp.json();
                    console.log('[YTDL-Worker] Piped response keys:', Object.keys(data));
                    
                    if (data && data.title && !data.error) {
                        // For allscan mode, collect formats from this instance
                        if (isAllScan) {
                            videoTitle = data.title || videoTitle;
                            videoAuthor = data.uploader || data.uploaderName || videoAuthor;
                            const lengthSeconds = data.duration || 0;
                            videoDuration = `${Math.floor(lengthSeconds / 60)}:${String(lengthSeconds % 60).padStart(2, '0')}`;
                            videoThumbnail = data.thumbnailUrl || videoThumbnail;
                            successfulApis.push(`Piped (${instance})`);
                            
                            // Collect audio formats
                            if (data.audioStreams && Array.isArray(data.audioStreams)) {
                                for (const stream of data.audioStreams) {
                                    if (!stream.url) continue;
                                    const codec = stream.codec || stream.mimeType?.split(';')[0]?.split('/')[1] || 'unknown';
                                    const container = codec.includes('opus') ? 'webm' : codec.includes('mp4a') ? 'm4a' : codec;
                                    allAudioFormats.push({
                                        url: stream.url,
                                        container: container,
                                        quality: stream.quality || `${stream.bitrate ? Math.round(stream.bitrate / 1000) + 'kbps' : 'Unknown'}`,
                                        type: 'audio',
                                        bitrate: stream.bitrate ? `${Math.round(stream.bitrate / 1000)}kbps` : '',
                                        source: `Piped`
                                    });
                                }
                            }
                            // Collect video formats
                            if (data.videoStreams && Array.isArray(data.videoStreams)) {
                                for (const stream of data.videoStreams) {
                                    if (!stream.url) continue;
                                    const container = stream.mimeType?.includes('webm') ? 'webm' : 'mp4';
                                    allVideoFormats.push({
                                        url: stream.url,
                                        container: container,
                                        quality: stream.videoOnly === false ? (stream.quality || 'Unknown') : `${stream.quality || 'Unknown'} (映像のみ)`,
                                        type: 'video',
                                        size: stream.contentLength ? `${Math.round(stream.contentLength / 1024 / 1024)}MB` : '',
                                        source: `Piped`
                                    });
                                }
                            }
                            // Continue to next instance for more options
                            continue;
                        }
                        
                        downloadData = {
                            status: 'piped',
                            piped: data,
                            instance: instance
                        };
                        successInstance = instance;
                        console.log('[YTDL-Worker] SUCCESS with Piped', instance, '- Title:', data.title);
                        break;
                    } else if (data.error) {
                        const err = `Piped ${instance}: ${data.error}`;
                        allErrors.push(err);
                        lastError = err;
                    } else {
                        const err = `Piped ${instance}: Unexpected response`;
                        allErrors.push(err);
                        lastError = err;
                    }
                } else {
                    const text = await resp.text();
                    const err = `Piped ${instance}: HTTP ${resp.status} - ${text.substring(0, 80)}`;
                    allErrors.push(err);
                    lastError = err;
                }
            } catch (e: any) {
                const err = `Piped ${instance}: ${e.message || e}`;
                allErrors.push(err);
                lastError = err;
            }
        }
        } // end if piped
        
        // ===== API 2: Invidious API instances (15 instances) =====
        if ((!downloadData && (apiOption === 'auto' || apiOption === 'invidious')) || isAllScan) {
            const invidiousInstances = [
                'https://inv.nadeko.net',
                'https://invidious.nerdvpn.de',
                'https://invidious.privacyredirect.com',
                'https://invidious.protokolla.fi',
                'https://inv.tux.pizza',
                'https://invidious.lunar.icu',
                'https://yt.artemislena.eu',
                'https://invidious.flokinet.to',
                'https://invidious.private.coffee',
                'https://vid.puffyan.us',
                'https://invidious.snopyta.org',
                'https://yewtu.be',
                'https://invidious.kavin.rocks',
                'https://inv.riverside.rocks',
                'https://invidious.osi.kr'
            ];
            
            console.log('[YTDL-Worker] Trying Invidious API instances...');
            
            for (const instance of invidiousInstances) {
                if (downloadData && !isAllScan) break;
                const apiUrl = `${instance}/api/v1/videos/${videoId}`;
                console.log('[YTDL-Worker] Trying Invidious:', apiUrl);
                
                try {
                    const resp = await fetch(apiUrl, {
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            'Accept': 'application/json'
                        }
                    });
                    
                    console.log('[YTDL-Worker] Invidious', instance, '-> Status:', resp.status);
                    
                    if (resp.ok) {
                        const data = await resp.json();
                        console.log('[YTDL-Worker] Invidious response keys:', Object.keys(data));
                        
                        if (data && data.title && !data.error) {
                            // For allscan mode, collect formats
                            if (isAllScan) {
                                videoTitle = data.title || videoTitle;
                                videoAuthor = data.author || videoAuthor;
                                const lengthSeconds = data.lengthSeconds || 0;
                                videoDuration = `${Math.floor(lengthSeconds / 60)}:${String(lengthSeconds % 60).padStart(2, '0')}`;
                                if (data.videoThumbnails && data.videoThumbnails.length > 0) {
                                    const thumbObj = data.videoThumbnails.find((t: any) => t.quality === 'medium') || data.videoThumbnails[0];
                                    videoThumbnail = thumbObj.url?.startsWith('/') ? `https://i.ytimg.com${thumbObj.url}` : thumbObj.url || videoThumbnail;
                                }
                                successfulApis.push(`Invidious (${instance})`);
                                
                                // Collect audio formats
                                if (data.adaptiveFormats) {
                                    for (const fmt of data.adaptiveFormats) {
                                        if (!fmt.url) continue;
                                        const isAudio = fmt.type?.startsWith('audio/');
                                        if (isAudio) {
                                            allAudioFormats.push({
                                                url: fmt.url,
                                                container: fmt.container || 'unknown',
                                                quality: fmt.audioQuality?.replace('AUDIO_QUALITY_', '') || 'Unknown',
                                                type: 'audio',
                                                bitrate: fmt.bitrate ? `${Math.round(parseInt(fmt.bitrate) / 1000)}kbps` : '',
                                                source: `Invidious`
                                            });
                                        }
                                    }
                                }
                                // Collect video formats
                                if (data.formatStreams) {
                                    for (const fmt of data.formatStreams) {
                                        if (!fmt.url) continue;
                                        allVideoFormats.push({
                                            url: fmt.url,
                                            container: fmt.container || 'mp4',
                                            quality: fmt.qualityLabel || fmt.quality || 'Unknown',
                                            type: 'video',
                                            size: fmt.size || '',
                                            source: `Invidious`
                                        });
                                    }
                                }
                                continue;
                            }
                            
                            downloadData = {
                                status: 'invidious',
                                invidious: data,
                                instance: instance
                            };
                            successInstance = instance;
                            console.log('[YTDL-Worker] SUCCESS with Invidious', instance, '- Title:', data.title);
                            break;
                        } else if (data.error) {
                            const err = `Invidious ${instance}: ${data.error}`;
                            allErrors.push(err);
                            lastError = err;
                        }
                    } else {
                        const text = await resp.text();
                        const err = `Invidious ${instance}: HTTP ${resp.status} - ${text.substring(0, 80)}`;
                        allErrors.push(err);
                        lastError = err;
                    }
                } catch (e: any) {
                    const err = `Invidious ${instance}: ${e.message || e}`;
                    allErrors.push(err);
                    lastError = err;
                }
            }
        }
        
        // ===== API 3: YT-DLP Web API (savetube style) =====
        if ((!downloadData && (apiOption === 'auto' || apiOption === 'vevioz')) || isAllScan) {
            const ytdlpWebApis = [
                { url: 'https://api.vevioz.com/api/json/channels?url=', type: 'vevioz' },
                { url: 'https://yt1s.com/api/ajaxSearch/index', type: 'yt1s' }
            ];
            
            console.log('[YTDL-Worker] Trying YT-DLP Web APIs...');
            
            // Try vevioz-style API
            try {
                const veviozUrl = `https://api.vevioz.com/api/button/mp4/${videoId}`;
                console.log('[YTDL-Worker] Trying Vevioz API:', veviozUrl);
                
                const resp = await fetch(veviozUrl, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': '*/*'
                    }
                });
                
                console.log('[YTDL-Worker] Vevioz -> Status:', resp.status);
                
                if (resp.ok) {
                    const text = await resp.text();
                    // Parse HTML response for download links
                    const linkMatches = text.match(/href="([^"]+)"/g);
                    const titleMatch = text.match(/<div class="title"[^>]*>([^<]+)<\/div>/i) || 
                                       text.match(/<h2[^>]*>([^<]+)<\/h2>/i);
                    
                    if (linkMatches && linkMatches.length > 0) {
                        const links = linkMatches.map(m => m.replace('href="', '').replace('"', ''))
                            .filter(l => l.startsWith('http') && !l.includes('vevioz.com'));
                        
                        if (links.length > 0) {
                            if (isAllScan) {
                                videoTitle = titleMatch ? titleMatch[1] : videoTitle;
                                successfulApis.push('Vevioz API');
                                for (let i = 0; i < links.length; i++) {
                                    allVideoFormats.push({
                                        url: links[i],
                                        container: 'mp4',
                                        quality: `Option ${i + 1}`,
                                        type: 'video',
                                        source: 'Vevioz'
                                    });
                                }
                            } else {
                                downloadData = {
                                    status: 'vevioz',
                                    vevioz: {
                                        title: titleMatch ? titleMatch[1] : `YouTube Video (${videoId})`,
                                        links: links
                                    },
                                    videoId: videoId
                                };
                                successInstance = 'Vevioz API';
                                console.log('[YTDL-Worker] SUCCESS with Vevioz - Found', links.length, 'links');
                            }
                        }
                    }
                } else {
                    allErrors.push(`Vevioz: HTTP ${resp.status}`);
                }
            } catch (e: any) {
                allErrors.push(`Vevioz: ${e.message || e}`);
            }
        }
        
        // ===== API 4: Cobalt API for YouTube (6 instances) =====
        if ((!downloadData && (apiOption === 'auto' || apiOption === 'cobalt')) || isAllScan) {
            console.log('[YTDL-Worker] Trying Cobalt API for YouTube...');
            
            const cobaltEndpoints = [
                'https://api.cobalt.tools',
                'https://cobalt-api.kwiatekmiki.com',
                'https://cobalt.canine.tools',
                'https://co.wuk.sh',
                'https://cobalt-api.hyper.lol',
                'https://cobalt.api.timelessnesses.me'
            ];
            
            for (const endpoint of cobaltEndpoints) {
                if (downloadData && !isAllScan) break;
                
                try {
                    console.log('[YTDL-Worker] Trying Cobalt:', endpoint);
                    
                    const resp = await fetch(`${endpoint}/`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        },
                        body: JSON.stringify({
                            url: fullYoutubeUrl,
                            videoQuality: '1080',
                            audioFormat: 'mp3',
                            filenameStyle: 'pretty'
                        })
                    });
                    
                    console.log('[YTDL-Worker] Cobalt', endpoint, '-> Status:', resp.status);
                    
                    if (resp.ok) {
                        const data = await resp.json();
                        console.log('[YTDL-Worker] Cobalt response:', JSON.stringify(data).substring(0, 200));
                        
                        if (data.status === 'tunnel' || data.status === 'redirect') {
                            if (isAllScan) {
                                successfulApis.push(`Cobalt (${endpoint})`);
                                allVideoFormats.push({
                                    url: data.url,
                                    container: data.filename?.split('.').pop() || 'mp4',
                                    quality: 'Best Quality',
                                    type: 'video',
                                    source: 'Cobalt'
                                });
                                continue;
                            }
                            downloadData = {
                                status: 'cobalt-yt',
                                cobalt: data,
                                videoId: videoId
                            };
                            successInstance = `Cobalt (${endpoint})`;
                            console.log('[YTDL-Worker] SUCCESS with Cobalt');
                            break;
                        } else if (data.status === 'picker' && data.picker) {
                            if (isAllScan) {
                                successfulApis.push(`Cobalt (${endpoint})`);
                                data.picker.forEach((item: any, idx: number) => {
                                    allVideoFormats.push({
                                        url: item.url,
                                        container: 'mp4',
                                        quality: item.type || `Item ${idx + 1}`,
                                        type: 'video',
                                        source: 'Cobalt'
                                    });
                                });
                                if (data.audio) {
                                    allAudioFormats.push({
                                        url: data.audio,
                                        container: 'mp3',
                                        quality: 'Audio',
                                        type: 'audio',
                                        source: 'Cobalt'
                                    });
                                }
                                continue;
                            }
                            downloadData = {
                                status: 'cobalt-yt',
                                cobalt: data,
                                videoId: videoId
                            };
                            successInstance = `Cobalt (${endpoint})`;
                            console.log('[YTDL-Worker] SUCCESS with Cobalt (picker)');
                            break;
                        } else {
                            allErrors.push(`Cobalt ${endpoint}: ${data.error?.code || data.status || 'Unknown'}`);
                        }
                    } else {
                        const text = await resp.text();
                        allErrors.push(`Cobalt ${endpoint}: HTTP ${resp.status}`);
                    }
                } catch (e: any) {
                    allErrors.push(`Cobalt ${endpoint}: ${e.message || e}`);
                }
            }
        }
        
        // ===== API 5: Y2Mate-style API =====
        if ((!downloadData && (apiOption === 'auto' || apiOption === 'y2mate')) || isAllScan) {
            console.log('[YTDL-Worker] Trying Y2Mate-style APIs...');
            
            // Try to get video info via alternative endpoints (4 services)
            const y2mateApis = [
                { name: 'Yt1s', analyzeUrl: 'https://www.yt1s.com/api/ajaxSearch/index', convertUrl: 'https://www.yt1s.com/api/ajaxConvert/convert' },
                { name: 'Y2Mate', analyzeUrl: 'https://www.y2mate.com/mates/analyzeV2/ajax', convertUrl: 'https://www.y2mate.com/mates/convertV2/index' },
                { name: 'SaveFrom', analyzeUrl: 'https://worker.sf-tools.com/savefrom.php', convertUrl: '' },
                { name: 'Loader.to', analyzeUrl: 'https://loader.to/api/card/', convertUrl: '' }
            ];
            
            for (const api of y2mateApis) {
                if (downloadData && !isAllScan) break;
                
                try {
                    console.log('[YTDL-Worker] Trying', api.name);
                    
                    // Step 1: Analyze
                    const analyzeResp = await fetch(api.analyzeUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                            'Origin': api.analyzeUrl.split('/api')[0],
                            'Referer': api.analyzeUrl.split('/api')[0] + '/'
                        },
                        body: `q=${encodeURIComponent(fullYoutubeUrl)}&vt=mp4`
                    });
                    
                    console.log('[YTDL-Worker]', api.name, 'analyze -> Status:', analyzeResp.status);
                    
                    if (analyzeResp.ok) {
                        const data = await analyzeResp.json();
                        console.log('[YTDL-Worker]', api.name, 'response keys:', Object.keys(data));
                        
                        if (data.status === 'ok' && data.title) {
                            if (isAllScan) {
                                videoTitle = data.title || videoTitle;
                                videoAuthor = data.a || videoAuthor;
                                successfulApis.push(api.name);
                                
                                // Parse links from y2mate response
                                if (data.links) {
                                    if (data.links.mp4) {
                                        Object.entries(data.links.mp4).forEach(([key, val]: [string, any]) => {
                                            if (val.q) {
                                                allVideoFormats.push({
                                                    url: val.k ? `#convert:${val.k}` : '',
                                                    container: 'mp4',
                                                    quality: val.q,
                                                    type: 'video',
                                                    size: val.size || '',
                                                    source: api.name
                                                });
                                            }
                                        });
                                    }
                                    if (data.links.mp3) {
                                        Object.entries(data.links.mp3).forEach(([key, val]: [string, any]) => {
                                            if (val.q) {
                                                allAudioFormats.push({
                                                    url: val.k ? `#convert:${val.k}` : '',
                                                    container: 'mp3',
                                                    quality: val.q,
                                                    type: 'audio',
                                                    size: val.size || '',
                                                    source: api.name
                                                });
                                            }
                                        });
                                    }
                                }
                                continue;
                            }
                            downloadData = {
                                status: 'y2mate',
                                y2mate: data,
                                videoId: videoId,
                                apiName: api.name
                            };
                            successInstance = api.name;
                            console.log('[YTDL-Worker] SUCCESS with', api.name, '- Title:', data.title);
                            break;
                        } else {
                            allErrors.push(`${api.name}: ${data.mess || 'Invalid response'}`);
                        }
                    } else {
                        allErrors.push(`${api.name}: HTTP ${analyzeResp.status}`);
                    }
                } catch (e: any) {
                    allErrors.push(`${api.name}: ${e.message || e}`);
                }
            }
        }
        
        // ===== AllScan mode: Return combined results =====
        if (isAllScan && (allAudioFormats.length > 0 || allVideoFormats.length > 0)) {
            console.log('[YTDL-Worker] AllScan complete. Audio formats:', allAudioFormats.length, 'Video formats:', allVideoFormats.length);
            
            // Remove duplicates by URL
            const seenUrls = new Set<string>();
            const uniqueAudioFormats = allAudioFormats.filter(f => {
                if (seenUrls.has(f.url)) return false;
                seenUrls.add(f.url);
                return true;
            });
            const uniqueVideoFormats = allVideoFormats.filter(f => {
                if (seenUrls.has(f.url)) return false;
                seenUrls.add(f.url);
                return true;
            });
            
            // Sort by source then quality
            uniqueAudioFormats.sort((a, b) => a.source.localeCompare(b.source));
            uniqueVideoFormats.sort((a, b) => a.source.localeCompare(b.source));
            
            // Generate AllScan result HTML
            const generateAllScanLinks = (formats: CollectedFormat[], icon: string) => {
                if (formats.length === 0) return '<div style="color:#999;">利用可能なフォーマットがありません</div>';
                
                // Group by source
                const bySource: Record<string, CollectedFormat[]> = {};
                for (const f of formats) {
                    if (!bySource[f.source]) bySource[f.source] = [];
                    bySource[f.source].push(f);
                }
                
                let html = '';
                for (const [source, fmts] of Object.entries(bySource)) {
                    html += `<div style="margin-top:10px;"><strong style="color:#009944;">${source}</strong></div>`;
                    for (const f of fmts) {
                        const label = f.type === 'audio' 
                            ? `${icon} ${f.container.toUpperCase()} (${f.quality}${f.bitrate ? ' - ' + f.bitrate : ''})`
                            : `${icon} ${f.container.toUpperCase()} ${f.quality}${f.size ? ' - ' + f.size : ''}`;
                        if (f.url.startsWith('#convert:')) {
                            html += `<div style="padding:8px 15px; margin:3px 0; background:#fff3cd; border-radius:4px; color:#856404; font-size:13px;">${label} ⚠️ 変換が必要</div>`;
                        } else {
                            html += `<a href="${f.url}" download style="display:block; padding:8px 15px; margin:3px 0; background:#f5f5f5; border-radius:4px; color:#333; text-decoration:none; font-size:13px; transition:background 0.2s;" onmouseover="this.style.background='#e8e8e8'" onmouseout="this.style.background='#f5f5f5'">${label}</a>`;
                        }
                    }
                }
                return html;
            };
            
            const allScanHtml = `
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${customTitle}</title>
                <style>
                    body { font-family: "Hiragino Kaku Gothic ProN", Meiryo, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; min-height: 100vh; }
                    .wrapper { width: 100%; max-width: 1000px; margin: 0 auto; padding: 20px; }
                    .pos-header { background: #fff; padding: 15px 25px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); display: flex; align-items: center; justify-content: space-between; }
                    .pos-header-logo { font-size: 20px; font-weight: bold; color: #667eea; }
                    .video-info { background: #fff; padding: 25px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); }
                    .video-header { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
                    .video-thumb { width: 300px; border-radius: 8px; }
                    .video-meta h1 { font-size: 18px; margin: 0 0 10px 0; color: #333; }
                    .video-meta p { margin: 5px 0; color: #666; font-size: 13px; }
                    .format-section { margin-top: 20px; padding: 15px; background: #f9f9f9; border-radius: 8px; }
                    .format-section h2 { font-size: 15px; color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 8px; margin: 0 0 10px 0; }
                    .back-link { display: inline-block; margin-bottom: 15px; color: #fff; text-decoration: none; font-weight: bold; }
                    .back-link:hover { text-decoration: underline; }
                    .api-badge { display: inline-block; padding: 3px 8px; background: #e8f5e9; color: #2e7d32; border-radius: 4px; font-size: 10px; margin: 2px; }
                    .stats { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 15px 20px; border-radius: 8px; color: #fff; margin-bottom: 20px; }
                    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 15px; text-align: center; }
                    .stats-item { font-size: 24px; font-weight: bold; }
                    .stats-label { font-size: 11px; opacity: 0.9; }
                    @media (max-width: 600px) {
                        .video-header { flex-direction: column; }
                        .video-thumb { width: 100%; }
                    }
                </style>
                <script>
                    let escCount = 0;
                    document.addEventListener('keydown', (e) => {
                        if (e.key === 'Escape') {
                            escCount++;
                            if (escCount >= 3) window.location.href = 'https://www.google.com';
                            setTimeout(() => escCount = 0, 1000);
                        }
                    });
                </script>
            </head>
            <body>
                <div class="wrapper">
                    <a href="/" class="back-link">← ホームに戻る</a>
                    <div class="pos-header">
                        <div class="pos-header-logo">🔍 全API スキャン結果</div>
                    </div>
                    
                    <div class="stats">
                        <div class="stats-grid">
                            <div>
                                <div class="stats-item">${successfulApis.length}</div>
                                <div class="stats-label">成功したAPI</div>
                            </div>
                            <div>
                                <div class="stats-item">${uniqueVideoFormats.length}</div>
                                <div class="stats-label">動画フォーマット</div>
                            </div>
                            <div>
                                <div class="stats-item">${uniqueAudioFormats.length}</div>
                                <div class="stats-label">音声フォーマット</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="video-info">
                        <div class="video-header">
                            <img src="${videoThumbnail}" alt="Thumbnail" class="video-thumb">
                            <div class="video-meta">
                                <h1>${videoTitle}</h1>
                                <p><strong>チャンネル:</strong> ${videoAuthor}</p>
                                <p><strong>再生時間:</strong> ${videoDuration}</p>
                                <p><strong>Video ID:</strong> ${videoId}</p>
                                <p style="margin-top: 10px;">
                                    <strong>成功したAPI:</strong><br>
                                    ${successfulApis.map(api => `<span class="api-badge">✓ ${api}</span>`).join('')}
                                </p>
                            </div>
                        </div>
                        
                        ${formatOption === 'all' || formatOption === 'audio' ? `
                        <div class="format-section">
                            <h2>🎵 音声ダウンロード (${uniqueAudioFormats.length}個)</h2>
                            ${generateAllScanLinks(uniqueAudioFormats, '🎵')}
                        </div>` : ''}
                        
                        ${formatOption === 'all' || formatOption === 'video' ? `
                        <div class="format-section">
                            <h2>🎬 動画ダウンロード (${uniqueVideoFormats.length}個)</h2>
                            ${generateAllScanLinks(uniqueVideoFormats, '🎬')}
                        </div>` : ''}
                        
                        <div style="margin-top: 20px; padding: 12px; background: #e3f2fd; border-radius: 6px; font-size: 11px; color: #1565c0;">
                            💡 全APIスキャンモードでは、利用可能なすべてのAPIからフォーマットを収集しました。<br>
                            ⚠️「変換が必要」のフォーマットは外部サイトでの追加処理が必要です。
                        </div>
                    </div>
                </div>
            </body>
            </html>
            `;
            
            return new Response(allScanHtml, {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
        
        // ===== API 6: Noembed for metadata + direct proxy links =====
        if (!downloadData) {
            console.log('[YTDL-Worker] All APIs failed, trying Noembed for metadata...');
            
            try {
                const noembedUrl = `https://noembed.com/embed?url=${encodeURIComponent(fullYoutubeUrl)}`;
                const resp = await fetch(noembedUrl, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                });
                
                if (resp.ok) {
                    const data = await resp.json();
                    if (data && data.title && !data.error) {
                        downloadData = {
                            status: 'noembed',
                            noembed: data,
                            videoId: videoId
                        };
                        successInstance = 'Noembed';
                        console.log('[YTDL-Worker] Got metadata from Noembed:', data.title);
                    }
                } else {
                    allErrors.push(`Noembed: HTTP ${resp.status}`);
                }
            } catch (e: any) {
                allErrors.push(`Noembed: ${e.message || e}`);
            }
        }
        
        // ===== Fallback: YouTube oEmbed for basic info =====
        if (!downloadData) {
            console.log('[YTDL-Worker] Trying YouTube oEmbed...');
            
            try {
                const oembedUrl = `https://www.youtube.com/oembed?url=${encodeURIComponent(fullYoutubeUrl)}&format=json`;
                const resp = await fetch(oembedUrl, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                });
                
                if (resp.ok) {
                    const data = await resp.json();
                    if (data && data.title) {
                        downloadData = {
                            status: 'oembed',
                            oembed: data,
                            videoId: videoId
                        };
                        successInstance = 'YouTube oEmbed';
                        console.log('[YTDL-Worker] Got basic info from oEmbed:', data.title);
                    }
                } else {
                    allErrors.push(`YouTube oEmbed: HTTP ${resp.status}`);
                }
            } catch (e: any) {
                allErrors.push(`YouTube oEmbed: ${e.message || e}`);
            }
        }
        
        console.log('[YTDL-Worker] Finished querying all instances. Success:', !!downloadData);
        
        if (!downloadData) {
            // Return a user-friendly error page with all errors
            const errorHtml = `
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <title>エラー - 東進学力ＰＯＳ</title>
                <style>
                    body { font-family: "Hiragino Kaku Gothic ProN", Meiryo, sans-serif; margin: 0; background: #f9f9f9; }
                    .wrapper { max-width: 700px; margin: 50px auto; padding: 20px; }
                    .error-box { background: #fff; border: 1px solid #ddd; padding: 30px; border-radius: 8px; }
                    h1 { color: #de5833; font-size: 20px; text-align: center; }
                    p { color: #666; text-align: center; }
                    a { color: #009944; }
                    .details { margin-top: 20px; padding: 15px; background: #f5f5f5; border-radius: 4px; font-size: 11px; color: #666; text-align: left; }
                    .details h3 { margin: 0 0 10px 0; font-size: 13px; color: #333; }
                    .error-item { padding: 5px 0; border-bottom: 1px solid #eee; word-break: break-all; }
                    .error-item:last-child { border-bottom: none; }
                </style>
            </head>
            <body>
                <div class="wrapper">
                    <div class="error-box">
                        <h1>⚠️ 動画情報の取得に失敗しました</h1>
                        <p>Video ID: <strong>${videoId}</strong></p>
                        <p>全てのサーバーへの接続に失敗しました。<br>動画が存在しないか、サーバーが一時的に利用できない可能性があります。</p>
                        <p><a href="/">← ホームに戻る</a></p>
                        <div class="details">
                            <h3>🔍 接続試行ログ (${allErrors.length}件のエラー)</h3>
                            ${allErrors.map((e, i) => `<div class="error-item">${i + 1}. ${e}</div>`).join('')}
                        </div>
                    </div>
                </div>
                <script>
                    console.log('[YTDL-Client] Error page loaded');
                    console.log('[YTDL-Client] Video ID:', '${videoId}');
                    console.log('[YTDL-Client] All errors:', ${JSON.stringify(allErrors)});
                </script>
            </body>
            </html>
            `;
            return new Response(errorHtml, { 
                status: 500,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
        
        // Process the download data based on source
        let title = 'Unknown Title';
        let author = 'Unknown';
        let duration = '0:00';
        let thumbnail = '';
        
        interface FormatInfo {
            url: string;
            container: string;
            quality: string;
            type: string;
            bitrate?: string;
            size?: string;
        }
        
        const audioFormats: FormatInfo[] = [];
        const videoFormats: FormatInfo[] = [];
        
        if (downloadData.status === 'piped' && downloadData.piped) {
            // Process Piped API response
            const piped = downloadData.piped;
            title = piped.title || 'Unknown Title';
            author = piped.uploader || piped.uploaderName || 'Unknown';
            const lengthSeconds = piped.duration || 0;
            duration = `${Math.floor(lengthSeconds / 60)}:${String(lengthSeconds % 60).padStart(2, '0')}`;
            thumbnail = piped.thumbnailUrl || `https://i.ytimg.com/vi/${videoId}/mqdefault.jpg`;
            
            // Process audioStreams
            if (piped.audioStreams && Array.isArray(piped.audioStreams)) {
                for (const stream of piped.audioStreams) {
                    if (!stream.url) continue;
                    const codec = stream.codec || stream.mimeType?.split(';')[0]?.split('/')[1] || 'unknown';
                    const container = codec.includes('opus') ? 'webm' : codec.includes('mp4a') ? 'm4a' : codec;
                    audioFormats.push({
                        url: stream.url,
                        container: container,
                        quality: stream.quality || `${stream.bitrate ? Math.round(stream.bitrate / 1000) + 'kbps' : 'Unknown'}`,
                        type: 'audio',
                        bitrate: stream.bitrate ? `${Math.round(stream.bitrate / 1000)}kbps` : ''
                    });
                }
            }
            
            // Process videoStreams (video only, no audio)
            if (piped.videoStreams && Array.isArray(piped.videoStreams)) {
                for (const stream of piped.videoStreams) {
                    if (!stream.url) continue;
                    // Only include streams with audio (videoOnly: false) or all for choice
                    if (stream.videoOnly === false) {
                        const container = stream.mimeType?.includes('webm') ? 'webm' : 'mp4';
                        videoFormats.push({
                            url: stream.url,
                            container: container,
                            quality: stream.quality || 'Unknown',
                            type: 'video',
                            size: stream.contentLength ? `${Math.round(stream.contentLength / 1024 / 1024)}MB` : ''
                        });
                    }
                }
            }
            
            // If no combined streams, add video-only with note
            if (videoFormats.length === 0 && piped.videoStreams) {
                for (const stream of piped.videoStreams) {
                    if (!stream.url) continue;
                    const container = stream.mimeType?.includes('webm') ? 'webm' : 'mp4';
                    videoFormats.push({
                        url: stream.url,
                        container: container,
                        quality: `${stream.quality || 'Unknown'} (映像のみ)`,
                        type: 'video',
                        size: stream.contentLength ? `${Math.round(stream.contentLength / 1024 / 1024)}MB` : ''
                    });
                }
            }
        } else if (downloadData.status === 'invidious' && downloadData.invidious) {
            // Process Invidious response
            const inv = downloadData.invidious;
            title = inv.title || 'Unknown Title';
            author = inv.author || 'Unknown';
            const lengthSeconds = inv.lengthSeconds || 0;
            duration = `${Math.floor(lengthSeconds / 60)}:${String(lengthSeconds % 60).padStart(2, '0')}`;
            
            if (inv.videoThumbnails && inv.videoThumbnails.length > 0) {
                const thumbObj = inv.videoThumbnails.find((t: any) => t.quality === 'medium') || inv.videoThumbnails[0];
                thumbnail = thumbObj.url;
                if (thumbnail.startsWith('/')) {
                    thumbnail = `https://i.ytimg.com${thumbnail}`;
                }
            }
            
            // Process adaptiveFormats (audio-only)
            if (inv.adaptiveFormats) {
                for (const fmt of inv.adaptiveFormats) {
                    if (!fmt.url) continue;
                    const isAudio = fmt.type?.startsWith('audio/');
                    if (isAudio) {
                        audioFormats.push({
                            url: fmt.url,
                            container: fmt.container || 'unknown',
                            quality: fmt.audioQuality?.replace('AUDIO_QUALITY_', '') || 'Unknown',
                            type: 'audio',
                            bitrate: fmt.bitrate ? `${Math.round(parseInt(fmt.bitrate) / 1000)}kbps` : ''
                        });
                    }
                }
            }
            
            // Process formatStreams (video+audio)
            if (inv.formatStreams) {
                for (const fmt of inv.formatStreams) {
                    if (!fmt.url) continue;
                    videoFormats.push({
                        url: fmt.url,
                        container: fmt.container || 'mp4',
                        quality: fmt.qualityLabel || fmt.quality || 'Unknown',
                        type: 'video',
                        size: fmt.size || ''
                    });
                }
            }
            
            // Also process adaptiveFormats for video
            if (inv.adaptiveFormats) {
                for (const fmt of inv.adaptiveFormats) {
                    if (!fmt.url) continue;
                    const isVideo = fmt.type?.startsWith('video/');
                    if (isVideo) {
                        videoFormats.push({
                            url: fmt.url,
                            container: fmt.container || 'mp4',
                            quality: `${fmt.qualityLabel || fmt.quality || 'Unknown'} (映像のみ)`,
                            type: 'video',
                            size: fmt.clen ? `${Math.round(parseInt(fmt.clen) / 1024 / 1024)}MB` : ''
                        });
                    }
                }
            }
        } else if (downloadData.status === 'vevioz' && downloadData.vevioz) {
            // Process Vevioz response (HTML links)
            title = downloadData.vevioz.title || `YouTube Video (${videoId})`;
            author = 'Unknown';
            duration = 'Unknown';
            thumbnail = `https://i.ytimg.com/vi/${videoId}/mqdefault.jpg`;
            
            if (downloadData.vevioz.links && downloadData.vevioz.links.length > 0) {
                for (let i = 0; i < downloadData.vevioz.links.length; i++) {
                    const link = downloadData.vevioz.links[i];
                    videoFormats.push({
                        url: link,
                        container: 'mp4',
                        quality: `Option ${i + 1}`,
                        type: 'video'
                    });
                }
            }
        } else if (downloadData.status === 'cobalt-yt' && downloadData.cobalt) {
            // Process Cobalt API response for YouTube
            title = `YouTube Video (${videoId})`;
            author = 'via Cobalt';
            duration = 'Unknown';
            thumbnail = `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`;
            
            if (downloadData.cobalt.status === 'tunnel' || downloadData.cobalt.status === 'redirect') {
                videoFormats.push({
                    url: downloadData.cobalt.url,
                    container: downloadData.cobalt.filename?.split('.').pop() || 'mp4',
                    quality: 'Best Quality',
                    type: 'video',
                    size: ''
                });
            } else if (downloadData.cobalt.status === 'picker' && downloadData.cobalt.picker) {
                downloadData.cobalt.picker.forEach((item: any, idx: number) => {
                    videoFormats.push({
                        url: item.url,
                        container: 'mp4',
                        quality: item.type || `Item ${idx + 1}`,
                        type: 'video'
                    });
                });
                if (downloadData.cobalt.audio) {
                    audioFormats.push({
                        url: downloadData.cobalt.audio,
                        container: 'mp3',
                        quality: 'Audio',
                        type: 'audio'
                    });
                }
            }
        } else if (downloadData.status === 'y2mate' && downloadData.y2mate) {
            // Process Y2Mate-style API response
            const y2data = downloadData.y2mate;
            title = y2data.title || `YouTube Video (${videoId})`;
            author = y2data.a || 'Unknown';
            duration = 'Unknown';
            thumbnail = `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`;
            
            // Parse links from y2mate response
            if (y2data.links) {
                // MP4 links
                if (y2data.links.mp4) {
                    Object.entries(y2data.links.mp4).forEach(([key, val]: [string, any]) => {
                        if (val.q) {
                            videoFormats.push({
                                url: val.k ? `#convert:${val.k}` : '',
                                container: 'mp4',
                                quality: val.q,
                                type: 'video',
                                size: val.size || ''
                            });
                        }
                    });
                }
                // MP3 links
                if (y2data.links.mp3) {
                    Object.entries(y2data.links.mp3).forEach(([key, val]: [string, any]) => {
                        if (val.q) {
                            audioFormats.push({
                                url: val.k ? `#convert:${val.k}` : '',
                                container: 'mp3',
                                quality: val.q,
                                type: 'audio',
                                size: val.size || ''
                            });
                        }
                    });
                }
            }
        } else if (downloadData.status === 'noembed' && downloadData.noembed) {
            // Process Noembed response (metadata only, suggest external tools)
            const noembed = downloadData.noembed;
            title = noembed.title || `YouTube Video (${videoId})`;
            author = noembed.author_name || 'Unknown';
            duration = 'Unknown';
            thumbnail = noembed.thumbnail_url || `https://i.ytimg.com/vi/${videoId}/mqdefault.jpg`;
            
            // No direct download links - will show alternative options
        } else if (downloadData.status === 'oembed' && downloadData.oembed) {
            // Process oEmbed response (metadata only)
            const oembed = downloadData.oembed;
            title = oembed.title || `YouTube Video (${videoId})`;
            author = oembed.author_name || 'Unknown';
            duration = 'Unknown';
            thumbnail = oembed.thumbnail_url || `https://i.ytimg.com/vi/${videoId}/mqdefault.jpg`;
            
            // No direct download links - will show alternative options
        }
        
        // Sort by quality
        audioFormats.sort((a, b) => {
            const order: Record<string, number> = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
            return (order[b.quality] || 0) - (order[a.quality] || 0);
        });
        
        // Generate download links HTML
        const generateLinks = (formats: FormatInfo[], icon: string) => {
            if (formats.length === 0) return '<div style="color:#999;">利用可能なフォーマットがありません</div>';
            return formats.map(f => {
                const filename = `${title.replace(/[^a-zA-Z0-9\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FFF]/g, '_')}.${f.container}`;
                const label = f.type === 'audio' 
                    ? `${icon} ${f.container.toUpperCase()} (${f.quality}${f.bitrate ? ' - ' + f.bitrate : ''})`
                    : `${icon} ${f.container.toUpperCase()} ${f.quality}${f.size ? ' - ' + f.size : ''}`;
                return `<a href="${f.url}" download="${filename}" style="display:block; padding:10px 15px; margin:5px 0; background:#f5f5f5; border-radius:4px; color:#333; text-decoration:none; font-size:14px; transition:background 0.2s;" onmouseover="this.style.background='#e8e8e8'" onmouseout="this.style.background='#f5f5f5'">${label}</a>`;
            }).join('');
        };
        
        // Build result HTML
        const noFormatsAvailable = audioFormats.length === 0 && videoFormats.length === 0;
        const isMetadataOnly = downloadData.status === 'oembed' || downloadData.status === 'noembed';
        
        const resultHtml = `
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${customTitle}</title>
            <style>
                body { font-family: "Hiragino Kaku Gothic ProN", Meiryo, sans-serif; margin: 0; background: #fff; color: #333; }
                .wrapper { width: 100%; max-width: 960px; margin: 0 auto; }
                .pos-header { padding: 10px 20px; border-bottom: 3px solid #009944; display: flex; align-items: center; justify-content: space-between; }
                .pos-header-logo { font-size: 22px; font-weight: bold; color: #009944; }
                .pos-body { padding: 40px 20px; background: #f9f9f9; min-height: 500px; }
                .video-info { background: #fff; padding: 30px; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
                .video-header { display: flex; gap: 20px; margin-bottom: 25px; }
                .video-thumb { width: 320px; border-radius: 8px; }
                .video-meta h1 { font-size: 20px; margin: 0 0 10px 0; color: #333; }
                .video-meta p { margin: 5px 0; color: #666; font-size: 14px; }
                .format-section { margin-top: 20px; }
                .format-section h2 { font-size: 16px; color: #009944; border-bottom: 2px solid #009944; padding-bottom: 8px; margin-bottom: 15px; }
                .back-link { display: inline-block; margin-bottom: 20px; color: #009944; text-decoration: none; font-weight: bold; }
                .back-link:hover { text-decoration: underline; }
                .pos-footer { text-align: center; padding: 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; background: #fff; }
                .api-badge { display: inline-block; padding: 3px 8px; background: #e8f5e9; color: #2e7d32; border-radius: 4px; font-size: 11px; margin-left: 10px; }
                .alt-section { margin-top: 25px; padding: 20px; background: #e3f2fd; border-radius: 8px; }
                .alt-section h3 { margin: 0 0 15px 0; font-size: 15px; color: #1565c0; }
                .alt-link { display: block; padding: 10px 15px; margin: 8px 0; background: #fff; border-radius: 6px; color: #1976d2; text-decoration: none; transition: all 0.2s; border: 1px solid #bbdefb; }
                .alt-link:hover { background: #e3f2fd; transform: translateX(5px); }
                @media (max-width: 600px) {
                    .video-header { flex-direction: column; }
                    .video-thumb { width: 100%; }
                }
            </style>
            <script>
                let escCount = 0;
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        escCount++;
                        if (escCount >= 3) window.location.href = 'https://www.google.com';
                        setTimeout(() => escCount = 0, 1000);
                    }
                });
            </script>
        </head>
        <body>
            <div class="wrapper">
                <div class="pos-header">
                    <div class="pos-header-logo">東進学力ＰＯＳ</div>
                </div>
                <div class="pos-body">
                    <a href="/" class="back-link">← ホームに戻る</a>
                    <div class="video-info">
                        <div class="video-header">
                            ${thumbnail ? `<img src="${thumbnail}" alt="Thumbnail" class="video-thumb">` : ''}
                            <div class="video-meta">
                                <h1>${title}</h1>
                                <p><strong>チャンネル:</strong> ${author}</p>
                                <p><strong>再生時間:</strong> ${duration}</p>
                                <p><strong>Video ID:</strong> ${videoId}</p>
                                <p><span class="api-badge">✓ ${successInstance}</span></p>
                            </div>
                        </div>
                        
                        ${!noFormatsAvailable ? `
                            ${formatOption === 'all' || formatOption === 'audio' ? `
                            <div class="format-section">
                                <h2>🎵 音声ダウンロード (Audio)</h2>
                                ${generateLinks(audioFormats, '🎵')}
                            </div>` : ''}
                            
                            ${formatOption === 'all' || formatOption === 'video' ? `
                            <div class="format-section">
                                <h2>🎬 動画ダウンロード (Video + Audio)</h2>
                                ${generateLinks(videoFormats, '🎬')}
                            </div>` : ''}
                            
                            ${formatOption === 'best' ? `
                            <div class="format-section">
                                <h2>⭐ 最高画質ダウンロード</h2>
                                ${videoFormats.length > 0 ? generateLinks([videoFormats[0]], '🎬') : '<div style="color:#999;">利用可能なフォーマットがありません</div>'}
                                ${audioFormats.length > 0 ? generateLinks([audioFormats[0]], '🎵') : ''}
                            </div>` : ''}
                        ` : ''}
                        
                        ${noFormatsAvailable || isMetadataOnly ? `
                        <div class="alt-section">
                            <h3>📥 代替ダウンロード方法</h3>
                            <p style="font-size: 13px; color: #666; margin-bottom: 15px;">
                                直接ダウンロードリンクを取得できませんでした。以下の外部サービスをお試しください：
                            </p>
                            <a href="https://cobalt.tools/?url=${encodeURIComponent(fullYoutubeUrl)}" target="_blank" class="alt-link">
                                🔷 Cobalt.tools で開く
                            </a>
                            <a href="https://y2mate.com/youtube/${videoId}" target="_blank" class="alt-link">
                                🟢 Y2Mate で開く
                            </a>
                            <a href="https://www.savefrom.net/?url=${encodeURIComponent(fullYoutubeUrl)}" target="_blank" class="alt-link">
                                🟡 SaveFrom.net で開く
                            </a>
                            <a href="https://ssyoutube.com/watch?v=${videoId}" target="_blank" class="alt-link">
                                🟠 SSYouTube で開く
                            </a>
                            <a href="https://9xbuddy.app/process?url=${encodeURIComponent(fullYoutubeUrl)}" target="_blank" class="alt-link">
                                🔴 9xBuddy で開く
                            </a>
                        </div>
                        ` : ''}
                        
                        <div style="margin-top: 25px; padding: 15px; background: #fff3cd; border-radius: 4px; font-size: 12px; color: #856404;">
                            ⚠️ ダウンロードリンクは一定時間後に無効になります。無効になった場合は再度取得してください。
                        </div>
                    </div>
                </div>
                <div class="pos-footer">Copyright (C) Nagase Brothers Inc.</div>
            </div>
        </body>
        </html>
        `;
        
        return new Response(resultHtml, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    // Check for Cobalt download request (for non-YouTube sites)
    const cobaltQueryObf = url.searchParams.get(PARAM_COBALT);
    if (cobaltQueryObf) {
        const cobaltQuery = deobfuscate(cobaltQueryObf);
        console.log('[Cobalt-Worker] Received request for:', cobaltQuery);
        
        let downloadResult: any = null;
        let cobaltError = '';
        let allAttempts: string[] = [];
        
        // Cobalt API endpoints (new API format uses POST /)
        const cobaltEndpoints = [
            'https://api.cobalt.tools',
            'https://cobalt-api.kwiatekmiki.com',
            'https://cobalt.canine.tools',
            'https://api.cobalt.lol'
        ];
        
        for (const endpoint of cobaltEndpoints) {
            try {
                console.log('[Cobalt-Worker] Trying:', endpoint);
                
                // New Cobalt API format (POST /)
                const resp = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    body: JSON.stringify({
                        url: cobaltQuery,
                        videoQuality: '1080',
                        audioFormat: 'mp3',
                        audioBitrate: '128',
                        filenameStyle: 'pretty',
                        downloadMode: 'auto',
                        tiktokFullAudio: true,
                        convertGif: true
                    })
                });
                
                console.log('[Cobalt-Worker]', endpoint, '-> Status:', resp.status);
                const respText = await resp.text();
                console.log('[Cobalt-Worker] Response:', respText.substring(0, 300));
                allAttempts.push(`${endpoint}: ${resp.status} - ${respText.substring(0, 100)}`);
                
                if (resp.ok) {
                    try {
                        const data = JSON.parse(respText);
                        
                        // New API response statuses: tunnel, redirect, picker, local-processing, error
                        if (data.status === 'tunnel' || data.status === 'redirect') {
                            downloadResult = data;
                            console.log('[Cobalt-Worker] SUCCESS with', endpoint);
                            break;
                        } else if (data.status === 'picker' && data.picker) {
                            downloadResult = data;
                            console.log('[Cobalt-Worker] PICKER SUCCESS with', endpoint);
                            break;
                        } else if (data.status === 'local-processing') {
                            // For local-processing, extract tunnel URLs
                            downloadResult = {
                                status: 'tunnel',
                                url: data.tunnel?.[0] || null,
                                tunnels: data.tunnel,
                                filename: data.output?.filename
                            };
                            if (downloadResult.url) {
                                console.log('[Cobalt-Worker] LOCAL-PROCESSING SUCCESS with', endpoint);
                                break;
                            }
                        } else if (data.status === 'error') {
                            cobaltError = data.error?.code || 'Unknown error';
                            console.log('[Cobalt-Worker] Error:', cobaltError);
                        }
                    } catch (parseErr) {
                        console.log('[Cobalt-Worker] Parse error:', parseErr);
                        cobaltError = 'Invalid JSON response';
                    }
                } else if (resp.status === 401 || resp.status === 403) {
                    cobaltError = 'このインスタンスは認証が必要です';
                }
            } catch (e: any) {
                console.log('[Cobalt-Worker] Error with', endpoint, ':', e.message);
                allAttempts.push(`${endpoint}: ${e.message}`);
                cobaltError = e.message;
            }
        }
        
        // Build Cobalt result page
        const cobaltResultHtml = `
        <!DOCTYPE html>
        <html lang="ja">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${customTitle}</title>
            <style>
                body { font-family: "Hiragino Kaku Gothic ProN", Meiryo, sans-serif; margin: 0; background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%); color: #333; min-height: 100vh; }
                .wrapper { width: 100%; max-width: 800px; margin: 0 auto; padding: 40px 20px; }
                .card { background: #fff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); overflow: hidden; }
                .card-header { padding: 20px 25px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; font-size: 18px; font-weight: bold; }
                .card-body { padding: 30px; }
                .back-link { display: inline-block; margin-bottom: 20px; color: #667eea; text-decoration: none; font-weight: bold; }
                .back-link:hover { text-decoration: underline; }
                .download-btn { display: block; width: 100%; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 10px; font-size: 16px; font-weight: bold; cursor: pointer; text-decoration: none; text-align: center; margin: 10px 0; transition: transform 0.2s, box-shadow 0.2s; }
                .download-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(102,126,234,0.4); }
                .error-box { background: #ffebee; color: #c62828; padding: 20px; border-radius: 10px; margin: 20px 0; }
                .url-info { background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; word-break: break-all; font-size: 13px; color: #666; }
                .picker-item { background: #f9f9f9; padding: 15px; border-radius: 10px; margin: 10px 0; display: flex; align-items: center; gap: 15px; }
                .picker-item img { max-width: 120px; border-radius: 8px; }
                .debug-info { margin-top: 20px; padding: 15px; background: #f0f0f0; border-radius: 8px; font-size: 11px; color: #666; }
                .debug-info pre { white-space: pre-wrap; word-break: break-all; margin: 5px 0; }
            </style>
            <script>
                let escCount = 0;
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        escCount++;
                        if (escCount >= 3) window.location.href = 'https://www.google.com';
                        setTimeout(() => escCount = 0, 1000);
                    }
                });
            </script>
        </head>
        <body>
            <div class="wrapper">
                <a href="/" class="back-link">← ホームに戻る</a>
                <div class="card">
                    <div class="card-header">🔗 Cobalt ダウンロード</div>
                    <div class="card-body">
                        <div class="url-info">
                            <strong>URL:</strong> ${cobaltQuery}
                        </div>
                        ${downloadResult ? `
                            ${(downloadResult.status === 'tunnel' || downloadResult.status === 'redirect') && downloadResult.url ? `
                                <a href="${downloadResult.url}" class="download-btn" target="_blank">
                                    ⬇️ ダウンロード開始${downloadResult.filename ? ` (${downloadResult.filename})` : ''}
                                </a>
                                <p style="text-align: center; color: #666; font-size: 13px; margin-top: 15px;">
                                    クリックでダウンロードが開始されます
                                </p>
                            ` : ''}
                            ${downloadResult.status === 'picker' && downloadResult.picker ? `
                                <p style="margin-bottom: 15px; font-weight: bold;">📦 複数のメディアが見つかりました:</p>
                                ${downloadResult.picker.map((item: any, i: number) => `
                                    <div class="picker-item">
                                        ${item.thumb ? `<img src="${item.thumb}" alt="thumb">` : ''}
                                        <div style="flex: 1;">
                                            <a href="${item.url}" class="download-btn" target="_blank" style="margin: 0;">
                                                ⬇️ ${item.type || 'ファイル'} ${i + 1}
                                            </a>
                                        </div>
                                    </div>
                                `).join('')}
                                ${downloadResult.audio ? `
                                    <div class="picker-item">
                                        <div style="flex: 1;">
                                            <a href="${downloadResult.audio}" class="download-btn" target="_blank" style="margin: 0; background: linear-gradient(135deg, #43a047 0%, #66bb6a 100%);">
                                                🎵 音声ダウンロード${downloadResult.audioFilename ? ` (${downloadResult.audioFilename})` : ''}
                                            </a>
                                        </div>
                                    </div>
                                ` : ''}
                            ` : ''}
                        ` : `
                            <div class="error-box">
                                <strong>❌ ダウンロードに失敗しました</strong><br><br>
                                ${cobaltError || 'このURLはサポートされていないか、サービスが利用できません。'}
                                <br><br>
                                <small>対応サイト: Twitter/X, TikTok, Instagram, Vimeo, SoundCloud, Reddit, Tumblr など</small>
                                <br><small>※ 公開APIインスタンスは認証が必要な場合があります</small>
                            </div>
                            <div class="debug-info">
                                <strong>デバッグ情報:</strong>
                                <pre>${allAttempts.join('\\n')}</pre>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        </body>
        </html>
        `;
        
        return new Response(cobaltResultHtml, {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    // Check for embedded search query
    const searchQuery = url.searchParams.get(PARAM_SEARCH);
    if (searchQuery) {
        // Fetch Google search results and rewrite links
        const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;
        
        const searchHeaders = new Headers();
        searchHeaders.set('User-Agent', isMobile 
            ? 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1'
            : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36');
        searchHeaders.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
        searchHeaders.set('Accept-Language', 'ja,en-US;q=0.9,en;q=0.8');
        
        try {
            const googleResponse = await fetch(googleUrl, { headers: searchHeaders });
            const googleHtml = await googleResponse.text();
            
            // Rewrite search result links to go through proxy
            let rewrittenHtml = googleHtml;
            
            // Rewrite href links
            rewrittenHtml = rewrittenHtml.replace(/href="(https?:\/\/[^"]+)"/g, (match, url) => {
                // Skip Google's own URLs
                if (url.includes('google.com') || url.includes('gstatic.com') || url.includes('googleapis.com')) {
                    return match;
                }
                const obfuscated = obfuscate(url);
                return `href="/?${PARAM_URL}=${obfuscated}"`;
            });
            
            // Rewrite /url?q= style Google redirect links
            rewrittenHtml = rewrittenHtml.replace(/href="\/url\?q=([^&"]+)[^"]*"/g, (match, encodedUrl) => {
                try {
                    const decodedUrl = decodeURIComponent(encodedUrl);
                    if (decodedUrl.startsWith('http')) {
                        const obfuscated = obfuscate(decodedUrl);
                        return `href="/?${PARAM_URL}=${obfuscated}"`;
                    }
                } catch(e) {}
                return match;
            });
            
            // Add custom title
            rewrittenHtml = rewrittenHtml.replace(/<title>[^<]*<\/title>/i, `<title>${customTitle}</title>`);
            
            // Inject proxy menu and panic button
            const menuHtml = `
            <div id="__proxy_menu_container" style="position: fixed; top: 0; right: 20px; z-index: 2147483647; font-family: sans-serif;">
                <div id="__proxy_menu_btn" style="background: #009944; color: white; padding: 5px 15px; border-radius: 0 0 5px 5px; cursor: pointer; font-weight: bold; font-size: 12px; box-shadow: 0 2px 5px rgba(0,0,0,0.2);">
                    Proxy Menu ▼
                </div>
                <div id="__proxy_menu_content" style="display: none; background: white; border: 1px solid #ccc; padding: 15px; border-radius: 5px; box-shadow: 0 5px 15px rgba(0,0,0,0.2); margin-top: 5px; text-align: left; width: 250px;">
                    <div style="margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid #eee;">
                        <a href="/" style="display: block; color: #009944; text-decoration: none; font-weight: bold; font-size: 14px;">🏠 Homeに戻る</a>
                    </div>
                    <form onsubmit="event.preventDefault(); doProxyNav(this.url.value);" style="display: flex; flex-direction: column; gap: 8px;">
                       <label style="font-size: 12px; color: #666;">URLを入力:</label>
                       <div style="display: flex; gap: 5px;">
                           <input name="url" placeholder="example.com" style="flex: 1; padding: 5px; border: 1px solid #ddd; border-radius: 3px; font-size: 12px;">
                           <button type="submit" style="background: #009944; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px;">Go</button>
                       </div>
                    </form>
                    <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; font-size: 11px; color: #999;">
                        <div style="color:#de5833; cursor:pointer; font-weight:bold;" onclick="window.location.href='https://www.google.com'">⚠ Panic Button</div>
                    </div>
                </div>
                <script>
                    (function(){
                        const btn = document.getElementById('__proxy_menu_btn');
                        const content = document.getElementById('__proxy_menu_content');
                        if(btn && content){
                            btn.onclick = function() {
                                content.style.display = content.style.display === 'none' ? 'block' : 'none';
                            };
                        }
                        let escCount = 0;
                        document.addEventListener('keydown', function(e) {
                            if (e.key === 'Escape') {
                                escCount++;
                                if (escCount >= 3) window.location.href = 'https://www.google.com';
                                setTimeout(function() { escCount = 0; }, 1000);
                            }
                        });
                        window.doProxyNav = function(input) {
                            if(!input) return;
                            const XOR_KEY = "${XOR_KEY}";
                            function xorProcess(str) {
                                let res = '';
                                for (let i = 0; i < str.length; i++) {
                                    res += String.fromCharCode(str.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
                                }
                                return res;
                            }
                            function obfuscate(u) {
                                const x = xorProcess(u);
                                return Array.from(x).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                            }
                            let target = input.trim();
                            const isUrl = /^https?:\\/\\//i.test(target) || /^([a-z0-9-]+\\.)+[a-z]{2,}(\\/.*)?$/i.test(target);
                            if (!isUrl) {
                                window.location.href = '/?__search=' + encodeURIComponent(target);
                            } else {
                                if (!target.startsWith('http://') && !target.startsWith('https://')) target = 'https://' + target;
                                window.location.href = '/?__url=' + obfuscate(target);
                            }
                        };
                    })();
                </script>
            </div>
            `;
            
            rewrittenHtml = rewrittenHtml.replace(/<body[^>]*>/i, (match) => match + menuHtml);
            
            return new Response(rewrittenHtml, {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        } catch (e) {
            return new Response(`Search Error: ${e}`, { status: 500 });
        }
    }

    // --- /downloads page: UI to manage download jobs ---
    if (pathname === '/downloads') {
      const downloadsHtml = `
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${customTitle} - ダウンロード管理</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: "Hiragino Kaku Gothic ProN", Meiryo, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; min-height: 100vh; }
    .wrapper { max-width: 900px; margin: 0 auto; padding: 30px 20px; }
    .back-link { display: inline-block; margin-bottom: 20px; color: #fff; text-decoration: none; font-weight: bold; }
    .back-link:hover { text-decoration: underline; }
    .card { background: #fff; border-radius: 16px; box-shadow: 0 8px 30px rgba(0,0,0,0.15); overflow: hidden; margin-bottom: 25px; }
    .card-header { padding: 20px 25px; background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: #fff; font-size: 18px; font-weight: bold; display: flex; align-items: center; gap: 10px; }
    .card-header.orange { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
    .card-header.blue { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
    .card-body { padding: 25px; }
    .form-group { margin-bottom: 18px; }
    .form-group label { display: block; font-weight: 600; margin-bottom: 8px; color: #444; font-size: 14px; }
    .form-group input, .form-group select { width: 100%; padding: 12px 14px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; transition: border-color 0.2s; }
    .form-group input:focus, .form-group select:focus { outline: none; border-color: #11998e; }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 14px 28px; font-size: 15px; font-weight: bold; border: none; border-radius: 10px; cursor: pointer; transition: all 0.3s; }
    .btn-submit { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: #fff; box-shadow: 0 4px 15px rgba(17,153,142,0.4); width: 100%; }
    .btn-submit:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(17,153,142,0.5); }
    .btn-submit:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    .job-list { margin-top: 20px; }
    .job-item { padding: 18px; border: 1px solid #eee; border-radius: 12px; margin-bottom: 12px; background: #fafafa; transition: all 0.2s; position: relative; overflow: hidden; }
    .job-item:hover { background: #f5f5f5; }
    .job-item.processing { border-left: 4px solid #2196f3; }
    .job-item.completed { border-left: 4px solid #4caf50; }
    .job-item.failed { border-left: 4px solid #f44336; }
    .job-item.pending { border-left: 4px solid #ff9800; }
    .job-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }
    .job-id { font-family: monospace; font-size: 11px; color: #888; background: #eee; padding: 4px 8px; border-radius: 4px; }
    .job-status { padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; display: flex; align-items: center; gap: 6px; }
    .job-status.pending { background: #fff3cd; color: #856404; }
    .job-status.processing { background: #cce5ff; color: #004085; }
    .job-status.completed { background: #d4edda; color: #155724; }
    .job-status.failed { background: #f8d7da; color: #721c24; }
    .spinner { width: 14px; height: 14px; border: 2px solid #004085; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .job-title { font-weight: 600; font-size: 15px; color: #333; margin-bottom: 8px; word-break: break-all; }
    .job-meta { font-size: 12px; color: #666; display: flex; flex-wrap: wrap; gap: 10px; }
    .job-meta span { display: flex; align-items: center; gap: 4px; }
    .job-actions { margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap; }
    .job-actions a { padding: 8px 16px; background: #667eea; color: #fff; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600; transition: background 0.2s; }
    .job-actions a:hover { background: #5a67d8; }
    .empty-state { text-align: center; padding: 40px; color: #999; }
    .empty-state span { font-size: 48px; display: block; margin-bottom: 15px; }
    .loading { text-align: center; padding: 30px; color: #666; }
    .error-msg { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
    .success-msg { background: #d4edda; color: #155724; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
    .progress-bar-container { height: 4px; background: #e0e0e0; border-radius: 2px; margin-top: 10px; overflow: hidden; }
    .progress-bar { height: 100%; background: linear-gradient(90deg, #4facfe, #00f2fe); animation: progress-anim 2s ease-in-out infinite; }
    @keyframes progress-anim { 0% { width: 0%; } 50% { width: 70%; } 100% { width: 100%; } }
    
    /* Usage Stats Card */
    .usage-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
    .usage-item { background: #f8f9fa; border-radius: 12px; padding: 20px; text-align: center; }
    .usage-item h4 { margin: 0 0 10px 0; font-size: 13px; color: #666; font-weight: 600; }
    .usage-value { font-size: 28px; font-weight: bold; color: #333; margin-bottom: 8px; }
    .usage-limit { font-size: 12px; color: #999; }
    .usage-bar { height: 8px; background: #e0e0e0; border-radius: 4px; margin-top: 12px; overflow: hidden; }
    .usage-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .usage-bar-fill.green { background: linear-gradient(90deg, #11998e, #38ef7d); }
    .usage-bar-fill.yellow { background: linear-gradient(90deg, #f7971e, #ffd200); }
    .usage-bar-fill.red { background: linear-gradient(90deg, #f5576c, #f093fb); }
    .refresh-btn { background: #eee; color: #333; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; margin-top: 15px; }
    .refresh-btn:hover { background: #ddd; }
    
    /* Status detail */
    .status-detail { font-size: 11px; color: #666; margin-top: 6px; padding: 8px 12px; background: #f5f5f5; border-radius: 6px; }
    .status-detail.error { background: #ffebee; color: #c62828; }
  </style>
</head>
<body>
  <div class="wrapper">
    <a href="/" class="back-link">← ホームに戻る</a>
    
    <!-- Usage Stats Card -->
    <div class="card">
      <div class="card-header blue">📊 使用状況</div>
      <div class="card-body">
        <div class="usage-grid">
          <div class="usage-item">
            <h4>☁️ R2 ストレージ使用量</h4>
            <div class="usage-value" id="r2-usage">--</div>
            <div class="usage-limit">無料枠: 10 GB / 月</div>
            <div class="usage-bar"><div class="usage-bar-fill green" id="r2-bar" style="width: 0%"></div></div>
          </div>
          <div class="usage-item">
            <h4>⚡ GitHub Actions 使用時間</h4>
            <div class="usage-value" id="actions-usage">--</div>
            <div class="usage-limit">無料枠: 2,000 分 / 月</div>
            <div class="usage-bar"><div class="usage-bar-fill green" id="actions-bar" style="width: 0%"></div></div>
          </div>
          <div class="usage-item">
            <h4>📦 今月のジョブ数</h4>
            <div class="usage-value" id="job-count">--</div>
            <div class="usage-limit">完了 / 処理中 / 失敗</div>
            <div class="usage-bar"><div class="usage-bar-fill green" id="job-bar" style="width: 0%"></div></div>
          </div>
        </div>
        <button class="refresh-btn" onclick="loadUsageStats()">🔄 使用状況を更新</button>
        <div style="margin-top: 12px; font-size: 11px; color: #888;">
          ※ R2 の使用量はジョブメタデータから推計しています。正確な値は Cloudflare ダッシュボードをご確認ください。
        </div>
      </div>
    </div>
    
    <div class="card">
      <div class="card-header">📥 新規ダウンロードリクエスト</div>
      <div class="card-body">
        <div id="form-message"></div>
        <form id="download-form">
          <div class="form-group">
            <label for="video-url">YouTube URL または Video ID</label>
            <input type="text" id="video-url" name="url" placeholder="https://www.youtube.com/watch?v=... または dQw4w9WgXcQ" required>
          </div>
          <div class="form-group">
            <label for="format">フォーマット (720p以下のみ対応)</label>
            <select id="format" name="format">
              <option value="720p">720p (推奨)</option>
              <option value="480p">480p</option>
              <option value="360p">360p</option>
              <option value="bestaudio">音声のみ (MP3)</option>
            </select>
          </div>
          <button type="submit" class="btn btn-submit" id="submit-btn">
            🚀 ダウンロード開始
          </button>
        </form>
        <div style="margin-top: 15px; padding: 12px; background: #fff3cd; border-radius: 8px; font-size: 12px; color: #856404;">
          ⚠️ GitHub Actions の無料枠節約のため、720p以下の画質に制限しています。処理には 2〜5 分かかります。
        </div>
      </div>
    </div>
    
    <div class="card">
      <div class="card-header orange">📋 ダウンロード履歴</div>
      <div class="card-body">
        <div id="job-list" class="job-list">
          <div class="loading">読み込み中...</div>
        </div>
        <button onclick="loadJobs()" class="btn" style="margin-top: 15px; background: #eee; color: #333;">🔄 履歴を更新</button>
        <div style="margin-top: 10px; font-size: 11px; color: #888;">
          処理中のジョブは自動的に 10 秒ごとに更新されます。
        </div>
      </div>
    </div>
  </div>
  
  <script>
    const form = document.getElementById('download-form');
    const submitBtn = document.getElementById('submit-btn');
    const formMsg = document.getElementById('form-message');
    const jobListEl = document.getElementById('job-list');
    let autoRefreshInterval = null;
    
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      formMsg.innerHTML = '';
      submitBtn.disabled = true;
      submitBtn.textContent = '⏳ 送信中...';
      
      const url = document.getElementById('video-url').value.trim();
      const format = document.getElementById('format').value;
      
      try {
        const resp = await fetch('/api/download/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ url, format, audio_only: format === 'bestaudio' })
        });
        const data = await resp.json();
        if (resp.ok && data.job_id) {
          formMsg.innerHTML = '<div class="success-msg">✅ リクエストを送信しました！ Job ID: <code>' + data.job_id + '</code><br><small>処理状況は下の履歴で確認できます。</small></div>';
          document.getElementById('video-url').value = '';
          loadJobs();
          startAutoRefresh();
        } else {
          formMsg.innerHTML = '<div class="error-msg">❌ エラー: ' + (data.error || '不明なエラー') + '</div>';
        }
      } catch (err) {
        formMsg.innerHTML = '<div class="error-msg">❌ 通信エラー: ' + err.message + '</div>';
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = '🚀 ダウンロード開始';
      }
    });
    
    function startAutoRefresh() {
      if (autoRefreshInterval) clearInterval(autoRefreshInterval);
      autoRefreshInterval = setInterval(() => {
        loadJobs(true);
      }, 10000);
    }
    
    async function loadJobs(silent = false) {
      if (!silent) jobListEl.innerHTML = '<div class="loading">読み込み中...</div>';
      try {
        const resp = await fetch('/api/download/list', { credentials: 'same-origin' });
        const data = await resp.json();
        if (!data.jobs || data.jobs.length === 0) {
          jobListEl.innerHTML = '<div class="empty-state"><span>📭</span>ダウンロード履歴がありません</div>';
          if (autoRefreshInterval) { clearInterval(autoRefreshInterval); autoRefreshInterval = null; }
          return;
        }
        // Sort by created_at desc
        data.jobs.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
        
        // Check if any job is processing
        const hasProcessing = data.jobs.some(j => j.status === 'pending' || j.status === 'processing');
        if (hasProcessing && !autoRefreshInterval) {
          startAutoRefresh();
        } else if (!hasProcessing && autoRefreshInterval) {
          clearInterval(autoRefreshInterval);
          autoRefreshInterval = null;
        }
        
        jobListEl.innerHTML = data.jobs.map(job => {
          const statusClass = job.status || 'pending';
          const statusIcons = { pending: '⏳', processing: '', completed: '✅', failed: '❌' };
          const statusLabels = { pending: '待機中', processing: 'ダウンロード中...', completed: '完了', failed: '失敗' };
          const statusIcon = statusIcons[statusClass] || '';
          const statusLabel = statusLabels[statusClass] || statusClass;
          const title = job.title || job.video_url || 'Unknown';
          const createdAt = job.created_at ? new Date(job.created_at).toLocaleString('ja-JP') : '-';
          const updatedAt = job.updated_at ? new Date(job.updated_at).toLocaleString('ja-JP') : '-';
          
          let actionsHtml = '';
          let statusDetailHtml = '';
          let progressHtml = '';
          
          if (job.status === 'completed' && job.filename) {
            actionsHtml = '<div class="job-actions"><a href="/video/' + job.job_id + '/' + encodeURIComponent(job.filename) + '" target="_blank">⬇️ ダウンロード</a></div>';
          } else if (job.status === 'failed') {
            statusDetailHtml = '<div class="status-detail error">❌ ' + escapeHtml(job.error || '処理中にエラーが発生しました') + '</div>';
          } else if (job.status === 'processing') {
            progressHtml = '<div class="progress-bar-container"><div class="progress-bar"></div></div>';
            statusDetailHtml = '<div class="status-detail">🔄 GitHub Actions でダウンロード処理中です...</div>';
          } else if (job.status === 'pending') {
            statusDetailHtml = '<div class="status-detail">⏳ ジョブがキューに追加されました。まもなく処理が開始されます。</div>';
          }
          
          const spinnerHtml = job.status === 'processing' ? '<div class="spinner"></div>' : '';
          
          return '<div class="job-item ' + statusClass + '">' +
            '<div class="job-header">' +
              '<span class="job-id">' + job.job_id + '</span>' +
              '<span class="job-status ' + statusClass + '">' + spinnerHtml + statusIcon + ' ' + statusLabel + '</span>' +
            '</div>' +
            '<div class="job-title">' + escapeHtml(title) + '</div>' +
            '<div class="job-meta">' +
              '<span>📅 作成: ' + createdAt + '</span>' +
              (job.format ? '<span>🎬 ' + job.format + '</span>' : '') +
              (job.filesize ? '<span>📦 ' + formatBytes(job.filesize) + '</span>' : '') +
            '</div>' +
            progressHtml +
            statusDetailHtml +
            actionsHtml +
          '</div>';
        }).join('');
        
        // Update usage stats
        updateJobStats(data.jobs);
      } catch (err) {
        if (!silent) jobListEl.innerHTML = '<div class="error-msg">読み込みエラー: ' + err.message + '</div>';
      }
    }
    
    function updateJobStats(jobs) {
      const completed = jobs.filter(j => j.status === 'completed').length;
      const processing = jobs.filter(j => j.status === 'processing' || j.status === 'pending').length;
      const failed = jobs.filter(j => j.status === 'failed').length;
      document.getElementById('job-count').textContent = completed + ' / ' + processing + ' / ' + failed;
      
      // Estimate R2 usage from filesizes
      const totalBytes = jobs.reduce((sum, j) => sum + (j.filesize || 0), 0);
      const r2GB = totalBytes / (1024 * 1024 * 1024);
      document.getElementById('r2-usage').textContent = r2GB.toFixed(2) + ' GB';
      const r2Percent = Math.min((r2GB / 10) * 100, 100);
      const r2Bar = document.getElementById('r2-bar');
      r2Bar.style.width = r2Percent + '%';
      r2Bar.className = 'usage-bar-fill ' + (r2Percent > 80 ? 'red' : r2Percent > 50 ? 'yellow' : 'green');
      
      // Estimate Actions usage (rough: 3 min per job)
      const totalJobs = completed + failed;
      const estMinutes = totalJobs * 3;
      document.getElementById('actions-usage').textContent = estMinutes + ' 分';
      const actionsPercent = Math.min((estMinutes / 2000) * 100, 100);
      const actionsBar = document.getElementById('actions-bar');
      actionsBar.style.width = actionsPercent + '%';
      actionsBar.className = 'usage-bar-fill ' + (actionsPercent > 80 ? 'red' : actionsPercent > 50 ? 'yellow' : 'green');
      
      // Job progress bar
      const jobTotal = jobs.length;
      const jobBar = document.getElementById('job-bar');
      jobBar.style.width = Math.min((completed / Math.max(jobTotal, 1)) * 100, 100) + '%';
    }
    
    async function loadUsageStats() {
      // Reload jobs to recalculate stats
      await loadJobs();
    }
    
    function escapeHtml(str) {
      return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function formatBytes(bytes) {
      if (!bytes) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Initial load
    loadJobs();
  </script>
</body>
</html>
      `;
      return new Response(downloadsHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // 1. Session Recovery (Cookie & Referer)
    // If PARAM_URL is missing, try to recover it from Cookies or Referer
    // We only recover if the user is NOT explicitly asking for the root proxy home (i.e., has other params or path)
    if (!queryUrl && (url.pathname !== '/' || [...url.searchParams.keys()].length > 0)) {
       // Try Cookie first (most reliable)
       const cookies = parseCookies(request.headers.get('Cookie'));
       if (cookies[PARAM_COOKIE]) {
         queryUrl = cookies[PARAM_COOKIE];
       }
       
       // Fallback to Referer if Cookie failed
       if (!queryUrl) {
          const referer = request.headers.get('Referer');
          if (referer) {
            try {
              const refererUrl = new URL(referer);
              if (refererUrl.origin === new URL(request.url).origin) {
                const refererQueryUrl = refererUrl.searchParams.get(PARAM_URL);
                if (refererQueryUrl) {
                   queryUrl = refererQueryUrl;
                }
              }
            } catch (e) {}
          }
       }
    }

    // 2. Root Access: Show Input Form
    // If still no queryUrl, show the form
    if (!queryUrl) {
        const html = `
      <!DOCTYPE html>
      <html lang="ja">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>東進学力ＰＯＳ</title>
        <style>
            * { box-sizing: border-box; }
            body { 
                font-family: "Hiragino Kaku Gothic ProN", "Noto Sans JP", Meiryo, sans-serif; 
                margin: 0; 
                background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
                color: #333; 
                min-height: 100vh;
            }
            .wrapper { width: 100%; max-width: 1100px; margin: 0 auto; }
            
            /* Header */
            .pos-header { 
                background: #fff;
                padding: 15px 30px; 
                border-bottom: 4px solid #009944; 
                display: flex; 
                align-items: center; 
                justify-content: space-between;
                box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            }
            .pos-header-logo { 
                font-size: 24px; 
                font-weight: bold; 
                color: #009944; 
                display: flex; 
                align-items: center; 
                gap: 12px;
                letter-spacing: 1px;
            }
            .pos-header-logo::before {
                content: "📚";
                font-size: 28px;
            }
            .header-links { font-size: 12px; color: #666; }
            .header-links a { 
                color: #009944; 
                text-decoration: none; 
                padding: 5px 10px;
                border-radius: 4px;
                transition: all 0.2s;
            }
            .header-links a:hover { background: #e8f5e9; }
            
            /* Main Body */
            .pos-body { 
                padding: 40px 20px 60px; 
                display: flex; 
                justify-content: center; 
                gap: 30px;
                flex-wrap: wrap;
            }
            
            /* Cards */
            .card {
                background: #fff;
                border-radius: 16px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                overflow: hidden;
                transition: transform 0.3s, box-shadow 0.3s;
            }
            .card:hover {
                transform: translateY(-3px);
                box-shadow: 0 8px 30px rgba(0,0,0,0.12);
            }
            .card-header {
                padding: 20px 25px;
                font-size: 16px;
                font-weight: bold;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .card-body { padding: 25px; }
            
            /* Main Card */
            .main-card { flex: 1; min-width: 400px; max-width: 600px; }
            .main-card .card-header { 
                background: linear-gradient(135deg, #009944 0%, #00b852 100%);
                color: #fff;
            }
            
            /* Side Card */
            .side-card { width: 350px; }
            .side-card .card-header {
                background: linear-gradient(135deg, #de5833 0%, #ff7043 100%);
                color: #fff;
            }
            .side-card.bookmarks .card-header {
                background: linear-gradient(135deg, #5c6bc0 0%, #7986cb 100%);
            }
            
            /* Input Styles */
            .input-group { margin-bottom: 20px; }
            .input-group label {
                display: block;
                font-weight: 600;
                margin-bottom: 8px;
                font-size: 14px;
                color: #444;
            }
            .input-group input[type="text"] {
                width: 100%;
                padding: 14px 16px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 15px;
                transition: all 0.3s;
                background: #fafafa;
            }
            .input-group input[type="text"]:focus {
                outline: none;
                border-color: #009944;
                background: #fff;
                box-shadow: 0 0 0 4px rgba(0,153,68,0.1);
            }
            
            /* Options */
            .options-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 12px;
                margin: 20px 0;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 12px;
            }
            .option-item {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 10px 12px;
                background: #fff;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.2s;
                border: 2px solid transparent;
            }
            .option-item:hover { border-color: #009944; }
            .option-item input[type="checkbox"] {
                width: 18px;
                height: 18px;
                accent-color: #009944;
            }
            .option-item span { font-size: 13px; color: #555; }
            
            /* Buttons */
            .btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                padding: 14px 28px;
                font-size: 15px;
                font-weight: bold;
                border: none;
                border-radius: 10px;
                cursor: pointer;
                transition: all 0.3s;
            }
            .btn-primary {
                background: linear-gradient(135deg, #009944 0%, #00b852 100%);
                color: #fff;
                box-shadow: 0 4px 15px rgba(0,153,68,0.3);
            }
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(0,153,68,0.4);
            }
            .btn-secondary {
                background: linear-gradient(135deg, #de5833 0%, #ff7043 100%);
                color: #fff;
                box-shadow: 0 4px 15px rgba(222,88,51,0.3);
            }
            .btn-secondary:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(222,88,51,0.4);
            }
            .btn-outline {
                background: #fff;
                color: #666;
                border: 2px solid #ddd;
            }
            .btn-outline:hover {
                border-color: #009944;
                color: #009944;
            }
            .btn-group {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
                justify-content: center;
                margin-top: 25px;
            }
            
            /* YouTube Section */
            .yt-input-row {
                display: flex;
                gap: 10px;
                margin-bottom: 15px;
            }
            .yt-input-row input {
                flex: 1;
                padding: 12px 14px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 14px;
                transition: all 0.3s;
            }
            .yt-input-row input:focus {
                outline: none;
                border-color: #de5833;
                box-shadow: 0 0 0 4px rgba(222,88,51,0.1);
            }
            .yt-options {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                margin-bottom: 12px;
            }
            .yt-option {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 8px 14px;
                background: #fff;
                border: 2px solid #eee;
                border-radius: 20px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s;
            }
            .yt-option:has(input:checked) {
                border-color: #de5833;
                background: #fff5f2;
            }
            .yt-option input { accent-color: #de5833; }
            
            /* Bookmarks */
            .bookmark-list { max-height: 200px; overflow-y: auto; }
            .bookmark-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 12px 15px;
                border-bottom: 1px solid #f0f0f0;
                transition: background 0.2s;
            }
            .bookmark-item:hover { background: #f8f9fa; }
            .bookmark-item:last-child { border-bottom: none; }
            .bookmark-item a {
                color: #5c6bc0;
                text-decoration: none;
                font-weight: 600;
                font-size: 14px;
            }
            .bookmark-item a:hover { text-decoration: underline; }
            .bookmark-delete {
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: #f5f5f5;
                border-radius: 50%;
                color: #999;
                cursor: pointer;
                transition: all 0.2s;
            }
            .bookmark-delete:hover { background: #ffebee; color: #e53935; }
            .bookmark-empty {
                padding: 30px;
                text-align: center;
                color: #999;
                font-size: 13px;
            }
            
            /* Footer */
            .pos-footer { 
                text-align: center; 
                padding: 25px; 
                font-size: 12px; 
                color: #888; 
                background: #fff;
                border-top: 1px solid #eee;
            }
            
            /* Notice */
            .notice {
                margin-top: 20px;
                padding: 15px;
                background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%);
                border-radius: 10px;
                font-size: 12px;
                color: #555;
                line-height: 1.6;
            }
            .notice strong { color: #d32f2f; }
            
            /* Title Input Special */
            .title-input-wrapper {
                margin-top: 15px;
                padding: 15px;
                background: #fff;
                border-radius: 8px;
            }
            .title-input-wrapper label {
                font-size: 12px;
                color: #666;
                margin-bottom: 6px;
                display: block;
            }
            .title-input-wrapper input {
                width: 100%;
                padding: 10px 12px;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                font-size: 13px;
            }
            
            /* Responsive */
            @media (max-width: 900px) {
                .pos-body { flex-direction: column; align-items: center; }
                .main-card, .side-card { width: 100%; max-width: 500px; min-width: auto; }
            }
            @media (max-width: 500px) {
                .pos-header { flex-direction: column; gap: 10px; text-align: center; }
                .btn-group { flex-direction: column; }
                .btn { width: 100%; }
            }
        </style>
        <script>
          const XOR_KEY = "${XOR_KEY}";
          const PARAM_URL = "${PARAM_URL}";
          const PARAM_LITE = "${PARAM_LITE}";
          const PARAM_TITLE = "${PARAM_TITLE}";
          const PARAM_UA_MOBILE = "${PARAM_UA_MOBILE}";
          const PARAM_NOIMG = "${PARAM_NOIMG}";

          function xorProcess(input) {
            let result = '';
            for (let i = 0; i < input.length; i++) {
              result += String.fromCharCode(input.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
            }
            return result;
          }
          function obfuscate(url) {
            const xored = xorProcess(url);
            return Array.from(xored).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
          }
          function go() {
            const input = document.getElementById('url').value.trim();
            if (!input) return;
            
            const isLite = document.getElementById('lite').checked;
            const noImg = document.getElementById('noimg').checked;
            const isMobile = document.getElementById('mobile').checked;
            const title = document.getElementById('title').value.trim();
            
            // Check if input is a valid URL format (simple check)
            const isUrl = /^https?:\/\//i.test(input) || /^([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(input);

            let dest;
            if (!isUrl) {
              // Use embedded Google search
              dest = '/?__search=' + encodeURIComponent(input);
            } else {
              let target = input;
              if (!target.startsWith('http://') && !target.startsWith('https://')) {
                target = 'https://' + target;
              }
              dest = '/?' + PARAM_URL + '=' + obfuscate(target);
            }
            
            if (isLite) dest += '&' + PARAM_LITE + '=1';
            if (noImg) dest += '&' + PARAM_NOIMG + '=1';
            if (isMobile) dest += '&' + PARAM_UA_MOBILE + '=1';
            if (title) dest += '&' + PARAM_TITLE + '=' + encodeURIComponent(title);
            
            window.location.href = dest;
          }
          function goDuck() {
            document.getElementById('url').value = 'https://duckduckgo.com';
            go();
          }
          
          function goYtdl() {
            const input = document.getElementById('yturl').value.trim();
            if (!input) return;
            
            // Get selected format option
            const formatOption = document.querySelector('input[name="ytformat"]:checked').value;
            const apiOption = document.querySelector('input[name="ytapi"]:checked').value;
            
            // Show progress overlay
            const progressOverlay = document.getElementById('yt-progress-overlay');
            const progressStatus = document.getElementById('yt-progress-status');
            const progressBar = document.getElementById('yt-progress-bar');
            progressOverlay.style.display = 'flex';
            
            // Progress animation
            let progress = 0;
            const progressSteps = [
              { percent: 10, text: 'URLを解析中...' },
              { percent: 30, text: 'API に接続中...' },
              { percent: 50, text: 'ビデオ情報を取得中...' },
              { percent: 70, text: 'ダウンロードリンクを生成中...' },
              { percent: 90, text: 'ページを準備中...' }
            ];
            
            let stepIndex = 0;
            const progressInterval = setInterval(() => {
              if (stepIndex < progressSteps.length) {
                progressBar.style.width = progressSteps[stepIndex].percent + '%';
                progressStatus.textContent = progressSteps[stepIndex].text;
                stepIndex++;
              }
            }, 600);
            
            console.log('[YTDL] Starting request for:', input, 'Format:', formatOption, 'API:', apiOption);
            
            // Obfuscate the video ID/URL
            const obfuscatedInput = obfuscate(input);
            
            // Navigate with format option using obfuscated parameter
            setTimeout(() => {
              clearInterval(progressInterval);
              progressBar.style.width = '100%';
              progressStatus.textContent = 'リダイレクト中...';
              window.location.href = '/?__m=' + obfuscatedInput + '&f=' + formatOption + '&api=' + apiOption;
            }, 3000);
          }
          
          function cancelYtdl() {
            document.getElementById('yt-progress-overlay').style.display = 'none';
          }
          
          function goCobalt() {
            const input = document.getElementById('cobalturl').value.trim();
            if (!input) return;
            
            // Show progress overlay
            const progressOverlay = document.getElementById('yt-progress-overlay');
            const progressStatus = document.getElementById('yt-progress-status');
            const progressBar = document.getElementById('yt-progress-bar');
            document.querySelector('#yt-progress-overlay > div > div:first-child').textContent = '🔗';
            document.querySelector('#yt-progress-overlay > div > div:nth-child(2)').textContent = 'Cobalt ダウンロード準備中';
            progressOverlay.style.display = 'flex';
            
            const progressSteps = [
              { percent: 20, text: 'URLを解析中...' },
              { percent: 50, text: 'Cobalt API に接続中...' },
              { percent: 80, text: 'ダウンロード情報を取得中...' }
            ];
            
            let stepIndex = 0;
            const progressInterval = setInterval(() => {
              if (stepIndex < progressSteps.length) {
                progressBar.style.width = progressSteps[stepIndex].percent + '%';
                progressStatus.textContent = progressSteps[stepIndex].text;
                stepIndex++;
              }
            }, 500);
            
            // Obfuscate and navigate
            const obfuscatedInput = obfuscate(input);
            setTimeout(() => {
              clearInterval(progressInterval);
              progressBar.style.width = '100%';
              progressStatus.textContent = 'リダイレクト中...';
              window.location.href = '/?__c=' + obfuscatedInput;
            }, 1500);
          }

          // --- Bookmarks Logic ---
          function loadBookmarks() {
            const list = document.getElementById('bookmark-list');
            list.innerHTML = '';
            const bookmarks = JSON.parse(localStorage.getItem('proxy_bookmarks') || '[]');
            if (bookmarks.length === 0) {
                list.innerHTML = '<div class="bookmark-empty">📭 ブックマークはありません<br><small>URLを入力して ⭐ ボタンで追加</small></div>';
                return;
            }
            bookmarks.forEach((b, index) => {
                const div = document.createElement('div');
                div.className = 'bookmark-item';
                
                const link = document.createElement('a');
                link.href = '#';
                link.textContent = b.title;
                link.onclick = (e) => {
                    e.preventDefault();
                    document.getElementById('url').value = b.url;
                    go();
                };
                
                const delBtn = document.createElement('span');
                delBtn.className = 'bookmark-delete';
                delBtn.textContent = '×';
                delBtn.onclick = () => removeBookmark(index);
                
                div.appendChild(link);
                div.appendChild(delBtn);
                list.appendChild(div);
            });
          }

          function addBookmark() {
             const url = document.getElementById('url').value.trim();
             if(!url) return;
             const title = prompt("コンテンツ名を入力してください (例: 数学I・A)", url);
             if(!title) return;
             
             const bookmarks = JSON.parse(localStorage.getItem('proxy_bookmarks') || '[]');
             bookmarks.push({ title, url });
             localStorage.setItem('proxy_bookmarks', JSON.stringify(bookmarks));
             loadBookmarks();
          }

          function removeBookmark(index) {
             const bookmarks = JSON.parse(localStorage.getItem('proxy_bookmarks') || '[]');
             bookmarks.splice(index, 1);
             localStorage.setItem('proxy_bookmarks', JSON.stringify(bookmarks));
             loadBookmarks();
          }

          // --- Panic Button Logic (Root Page) ---
          let escCount = 0;
          document.addEventListener('keydown', (e) => {
             if (e.key === 'Escape') {
                 escCount++;
                 if (escCount >= 3) {
                     window.location.href = 'https://www.google.com';
                 }
                 setTimeout(() => escCount = 0, 1000);
             }
          });

          window.onload = loadBookmarks;
        </script>
      </head>
      <body>
        <div class="wrapper">
          <div class="pos-header">
            <div class="pos-header-logo">
              <span>東進学力ＰＯＳ</span>
            </div>
            <div class="header-links">
              <a href="/downloads">📥 ダウンロード管理</a>
              <a href="#">📖 利用ガイド</a>
              <a href="#">❓ FAQ</a>
            </div>
          </div>
          
          <div class="pos-body">
            <!-- Main Card: Proxy -->
            <div class="card main-card">
              <div class="card-header">
                🌐 Web Proxy - プロキシ接続
              </div>
              <div class="card-body">
                <form onsubmit="event.preventDefault(); go();">
                  <div class="input-group">
                    <label>🔗 URL / 検索キーワード</label>
                    <input type="text" id="url" placeholder="https://example.com または 検索ワード" required>
                  </div>
                  
                  <div class="options-grid">
                    <label class="option-item">
                      <input type="checkbox" id="lite" onchange="if(this.checked) document.getElementById('noimg').checked=false">
                      <span>⚡ 軽量モード</span>
                    </label>
                    <label class="option-item">
                      <input type="checkbox" id="noimg" onchange="if(this.checked) document.getElementById('lite').checked=false">
                      <span>🚫 画像なし</span>
                    </label>
                    <label class="option-item">
                      <input type="checkbox" id="mobile">
                      <span>📱 モバイル偽装</span>
                    </label>
                    <div class="title-input-wrapper" style="grid-column: 1 / -1;">
                      <label>📝 表示タイトル（偽装用）</label>
                      <input type="text" id="title" placeholder="任意のタイトル" value="東進学力ＰＯＳ">
                    </div>
                  </div>

                  <div class="btn-group">
                    <button type="submit" class="btn btn-primary">🚀 アクセス開始</button>
                    <button type="button" onclick="goDuck()" class="btn btn-secondary">🦆 DuckDuckGo</button>
                    <button type="button" onclick="addBookmark()" class="btn btn-outline">⭐ ブックマーク</button>
                  </div>
                </form>
                
                <div class="notice">
                  💡 URLを入力するとプロキシ経由でアクセス、キーワードを入力するとGoogle検索を実行します。<br>
                  🚨 緊急時は <strong>Escキーを3回連打</strong> でGoogleへ移動します。
                </div>
              </div>
            </div>
            
            <!-- Side Cards -->
            <div style="display: flex; flex-direction: column; gap: 20px; width: 350px;">
              <!-- YouTube Card -->
              <div class="card side-card">
                <div class="card-header">
                  🎬 YouTube ダウンロード
                </div>
                <div class="card-body">
                  <div class="yt-input-row">
                    <input type="text" id="yturl" placeholder="YouTube URL または Video ID">
                    <button type="button" onclick="goYtdl()" class="btn btn-secondary" style="padding: 12px 20px; white-space: nowrap;">取得</button>
                  </div>
                  
                  <div class="yt-options">
                    <label class="yt-option">
                      <input type="radio" name="ytformat" value="all" checked> すべて
                    </label>
                    <label class="yt-option">
                      <input type="radio" name="ytformat" value="video"> 🎥 動画
                    </label>
                    <label class="yt-option">
                      <input type="radio" name="ytformat" value="audio"> 🎵 音声
                    </label>
                    <label class="yt-option">
                      <input type="radio" name="ytformat" value="best"> ⭐ 最高
                    </label>
                  </div>
                  
                  <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #eee;">
                    <div style="font-size: 12px; color: #666; margin-bottom: 8px;">🔧 API選択:</div>
                    <div class="yt-options" style="flex-wrap: wrap;">
                      <label class="yt-option" style="border-color: #43a047;">
                        <input type="radio" name="ytapi" value="auto" checked> 🔄 自動
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="piped"> 🟢 Piped
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="invidious"> 🟣 Invidious
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="vevioz"> 🟠 Vevioz
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="cobalt"> 🔷 Cobalt
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="y2mate"> 🔶 Y2Mate
                      </label>
                      <label class="yt-option" style="border-color: #e91e63; background: linear-gradient(135deg, #fce4ec 0%, #f3e5f5 100%);">
                        <input type="radio" name="ytapi" value="allscan"> 🔍 全取得
                      </label>
                    </div>
                    <div style="font-size: 10px; color: #e91e63; margin-top: 5px; text-align: center;">
                      ※ 全取得: すべてのAPIを回して全フォーマットを表示
                    </div>
                  </div>
                  
                  <div style="font-size: 11px; color: #999; text-align: center; margin-top: 10px;">
                    youtube.com, youtu.be, shorts に対応
                  </div>
                </div>
              </div>
              
              <!-- Cobalt Card -->
              <div class="card side-card" style="border-top: 4px solid #667eea;">
                <div class="card-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                  🔗 その他サイト (Cobalt)
                </div>
                <div class="card-body">
                  <div class="yt-input-row">
                    <input type="text" id="cobalturl" placeholder="Twitter, TikTok, Instagram...">
                    <button type="button" onclick="goCobalt()" class="btn" style="padding: 12px 20px; white-space: nowrap; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff;">取得</button>
                  </div>
                  <div style="font-size: 11px; color: #999; text-align: center; line-height: 1.5;">
                    Twitter/X, TikTok, Instagram, Vimeo,<br>SoundCloud, Reddit, Tumblr 等
                  </div>
                </div>
              </div>
              
              <!-- Bookmarks Card -->
              <div class="card side-card bookmarks">
                <div class="card-header">
                  📚 ブックマーク
                </div>
                <div class="card-body" style="padding: 0;">
                  <div id="bookmark-list" class="bookmark-list">
                    <!-- Bookmarks will be loaded here -->
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <!-- Progress Overlay -->
          <div id="yt-progress-overlay" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); justify-content: center; align-items: center; z-index: 9999; backdrop-filter: blur(5px);">
            <div style="background: #fff; padding: 50px 60px; border-radius: 20px; text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.4); min-width: 380px;">
              <div style="font-size: 60px; margin-bottom: 20px;">🎬</div>
              <div style="font-size: 20px; font-weight: bold; color: #333; margin-bottom: 25px;">YouTube ダウンロード準備中</div>
              <div style="background: #f0f0f0; border-radius: 12px; height: 14px; overflow: hidden; margin-bottom: 20px;">
                <div id="yt-progress-bar" style="background: linear-gradient(90deg, #de5833, #ff7043); height: 100%; width: 0%; transition: width 0.4s ease; border-radius: 12px;"></div>
              </div>
              <div id="yt-progress-status" style="color: #666; font-size: 15px; margin-bottom: 25px;">準備中...</div>
              <button type="button" onclick="cancelYtdl()" class="btn btn-outline" style="padding: 10px 30px;">キャンセル</button>
            </div>
          </div>
          
          <div class="pos-footer">
            Copyright (C) Nagase Brothers Inc. | 学習支援システム
          </div>
        </div>
      </body>
      </html>
      `;
      return new Response(html, { headers: { 'Content-Type': 'text/html' } });
    }

    // 2. Proxy Logic
    let targetUrlStr = '';
    try {
      targetUrlStr = deobfuscate(queryUrl);
      // Basic validation
      if (!targetUrlStr.startsWith('http')) {
         throw new Error('Invalid protocol');
      }
      
      // Merge extra query parameters from the request URL to the target URL
      // This fixes search engine queries (e.g. /?__url=...&q=search_term)
      const targetUrlObj = new URL(targetUrlStr);
      url.searchParams.forEach((value, key) => {
        if (key !== PARAM_URL && key !== PARAM_LITE && key !== PARAM_TITLE) {
          targetUrlObj.searchParams.append(key, value);
        }
      });
      targetUrlStr = targetUrlObj.toString();

    } catch (e) {
      return new Response('Invalid URL or Obfuscation Error', { status: 400 });
    }

    // Fix for DuckDuckGo and other sites that might reject specific headers or need specific handling
    const targetUrl = new URL(targetUrlStr);

    // Prepare Request
    const newRequestHeaders = new Headers();
    // Only copy safe headers
    // Added 'cookie' to safe headers might be needed for some session flows but generally risky for proxy anonymity.
    // For DuckDuckGo, sometimes lack of certain headers causes issues.
    const safeHeaders = [
      'accept', 'accept-language', 'user-agent', 'cache-control', 'pragma',
      'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
      'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
      'upgrade-insecure-requests'
    ];
    for (const [key, value] of request.headers) {
      if (safeHeaders.includes(key.toLowerCase())) {
        newRequestHeaders.set(key, value);
      }
    }
    
    newRequestHeaders.set('Referer', targetUrl.origin);
    
    if (isMobile) {
        newRequestHeaders.set('User-Agent', 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1');
    } else if (!newRequestHeaders.has('User-Agent')) {
       newRequestHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36');
    }

    // Re-create request with correct options
    // Do NOT set Host header manually, let fetch handle it to avoid issues with redirects
    const finalRequest = new Request(targetUrlStr, {
        method: request.method,
        headers: newRequestHeaders,
        body: (request.method !== 'GET' && request.method !== 'HEAD') ? request.body : null,
        redirect: 'follow'
    });

    try {
      const response = await fetch(finalRequest);
      
      const newResponse = new Response(response.body, response);
      
      // Session Persistence: Set Cookie
      // Only update session cookie if this looks like a page navigation (HTML request)
      // This prevents subresources (scripts, images) from overwriting the current page URL in the cookie
      const acceptHeader = request.headers.get('Accept') || '';
      const isPageNavigation = acceptHeader.includes('text/html');

      if (isPageNavigation) {
        if (queryUrl) {
            newResponse.headers.append('Set-Cookie', `${PARAM_COOKIE}=${queryUrl}; Path=/; HttpOnly; SameSite=Lax`);
        }
        if (customTitle) {
            newResponse.headers.append('Set-Cookie', `${PARAM_TITLE_COOKIE}=${encodeURIComponent(customTitle)}; Path=/; HttpOnly; SameSite=Lax`);
        }
        // Always update Lite cookie on navigation
        newResponse.headers.append('Set-Cookie', `${PARAM_LITE_COOKIE}=${isLite ? '1' : '0'}; Path=/; HttpOnly; SameSite=Lax`);
        // Always update UA cookie on navigation
        newResponse.headers.append('Set-Cookie', `${PARAM_UA_COOKIE}=${isMobile ? '1' : '0'}; Path=/; HttpOnly; SameSite=Lax`);
        // Always update NoImg cookie on navigation
        newResponse.headers.append('Set-Cookie', `${PARAM_NOIMG_COOKIE}=${noImg ? '1' : '0'}; Path=/; HttpOnly; SameSite=Lax`);
      }

      // CORS & Security Headers
      newResponse.headers.set('Access-Control-Allow-Origin', '*');
      newResponse.headers.delete('Content-Security-Policy');
      newResponse.headers.delete('Content-Security-Policy-Report-Only');
      newResponse.headers.delete('X-Frame-Options');
      newResponse.headers.delete('X-Content-Type-Options');
      // Remove strict transport security to allow http proxying if needed, though we use https mostly
      newResponse.headers.delete('Strict-Transport-Security');
      // Remove Referrer-Policy to encourage browsers to send Referer
      newResponse.headers.delete('Referrer-Policy');

      // 3. CSS Rewriting (Simple Regex)
      const contentType = newResponse.headers.get('content-type');
      if (contentType && contentType.includes('text/css')) {
        const cssText = await newResponse.text();
        const rewrittenCss = cssText.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, url) => {
          if (url.startsWith('data:') || url.startsWith('#')) return match;
          try {
            const absoluteUrl = new URL(url, targetUrlStr).toString();
            const obfuscated = obfuscate(absoluteUrl);
            return `url('/?${PARAM_URL}=${obfuscated}')`;
          } catch (e) {
            return match;
          }
        });
        return new Response(rewrittenCss, newResponse);
      }

      // 4. HTML Rewriting
      if (contentType && contentType.includes('text/html')) {
        let rewriter = new HTMLRewriter()
          .on('meta', new MetaRefreshRewriter(targetUrlStr))
          .on('a', new AttributeRewriter('href', targetUrlStr))
          .on('area', new AttributeRewriter('href', targetUrlStr))
          .on('link', new AttributeRewriter('href', targetUrlStr))
          .on('form', new FormRewriter(targetUrlStr, isLite, customTitle))
          .on('script', new AdBlockRewriter())
          .on('iframe', new AdBlockRewriter())
          .on('img', new AdBlockRewriter());

        // Inject Control Menu
        rewriter = rewriter.on('body', {
            element(element) {
                const menuHtml = `
                <div id="__proxy_menu_container" style="position: fixed; top: 0; right: 20px; z-index: 2147483647; font-family: sans-serif;">
                    <div id="__proxy_menu_btn" style="background: #009944; color: white; padding: 5px 15px; border-radius: 0 0 5px 5px; cursor: pointer; font-weight: bold; font-size: 12px; box-shadow: 0 2px 5px rgba(0,0,0,0.2);">
                        Proxy Menu ▼
                    </div>
                    <div id="__proxy_menu_content" style="display: none; background: white; border: 1px solid #ccc; padding: 15px; border-radius: 5px; box-shadow: 0 5px 15px rgba(0,0,0,0.2); margin-top: 5px; text-align: left; width: 250px;">
                        <div style="margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid #eee;">
                            <a href="/" style="display: block; color: #009944; text-decoration: none; font-weight: bold; font-size: 14px;">🏠 Homeに戻る</a>
                        </div>
                        <form onsubmit="event.preventDefault(); doProxyNav(this.url.value);" style="display: flex; flex-direction: column; gap: 8px;">
                           <label style="font-size: 12px; color: #666;">URLを入力:</label>
                           <div style="display: flex; gap: 5px;">
                               <input name="url" placeholder="example.com" style="flex: 1; padding: 5px; border: 1px solid #ddd; border-radius: 3px; font-size: 12px;">
                               <button type="submit" style="background: #009944; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px;">Go</button>
                           </div>
                        </form>
                        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; font-size: 11px; color: #999;">
                            <div>Lite Mode: ${isLite ? 'ON' : 'OFF'}</div>
                            <div>No Image: ${noImg ? 'ON' : 'OFF'}</div>
                            <div>Mobile UA: ${isMobile ? 'ON' : 'OFF'}</div>
                            <div style="margin-top:5px; color:#de5833; cursor:pointer; font-weight:bold;" onclick="window.location.href='https://www.google.com'">⚠ Panic Button</div>
                        </div>
                    </div>
                    <script>
                        (function(){
                            const btn = document.getElementById('__proxy_menu_btn');
                            const content = document.getElementById('__proxy_menu_content');
                            if(btn && content){
                                btn.onclick = function() {
                                    content.style.display = content.style.display === 'none' ? 'block' : 'none';
                                };
                            }
                            
                            // Panic Key Listener
                            let escCount = 0;
                            document.addEventListener('keydown', function(e) {
                                if (e.key === 'Escape') {
                                    escCount++;
                                    if (escCount >= 3) {
                                        window.location.href = 'https://www.google.com';
                                    }
                                    setTimeout(function() { escCount = 0; }, 1000);
                                }
                            });

                            window.doProxyNav = function(input) {
                                if(!input) return;
                                const XOR_KEY = "${XOR_KEY}";
                                const PARAM_URL = "${PARAM_URL}";
                                const PARAM_LITE = "${PARAM_LITE}";
                                const PARAM_TITLE = "${PARAM_TITLE}";
                                const PARAM_UA_MOBILE = "${PARAM_UA_MOBILE}";
                                const PARAM_NOIMG = "${PARAM_NOIMG}";
                                
                                function xorProcess(str) {
                                    let res = '';
                                    for (let i = 0; i < str.length; i++) {
                                        res += String.fromCharCode(str.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
                                    }
                                    return res;
                                }
                                function obfuscate(u) {
                                    const x = xorProcess(u);
                                    return Array.from(x).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                                }
                                
                                let target = input.trim();
                                const isUrl = /^https?:\\/\\//i.test(target) || /^([a-z0-9-]+\\.)+[a-z]{2,}(\\/.*)?$/i.test(target);
                                let dest;
                                if (!isUrl) {
                                    dest = '/?__search=' + encodeURIComponent(target);
                                } else {
                                    if (!target.startsWith('http://') && !target.startsWith('https://')) {
                                        target = 'https://' + target;
                                    }
                                    dest = '/?' + PARAM_URL + '=' + obfuscate(target);
                                }
                                if (${isLite}) dest += '&' + PARAM_LITE + '=1';
                                if (${noImg}) dest += '&' + PARAM_NOIMG + '=1';
                                if (${isMobile}) dest += '&' + PARAM_UA_MOBILE + '=1';
                                // Title is handled by cookie now, but we can pass it if needed
                                window.location.href = dest;
                            };
                        })();
                    </script>
                </div>
                `;
                element.prepend(menuHtml, { html: true });
            }
        });

        // Title Rewriting
        if (customTitle) {
          rewriter = rewriter.on('title', {
            element(element) {
              element.setInnerContent(customTitle);
            }
          });
        }

        if (isLite) {
          // Lightweight Mode: Remove heavy elements
          rewriter = rewriter
            .on('script', { element: el => el.remove() })
            .on('img', { element: el => el.remove() })
            .on('video', { element: el => el.remove() })
            .on('audio', { element: el => el.remove() })
            .on('iframe', { element: el => el.remove() })
            .on('object', { element: el => el.remove() })
            .on('embed', { element: el => el.remove() });
        } else if (noImg) {
          // No Image Mode: Remove images but keep scripts
          rewriter = rewriter
            .on('img', { element: el => el.remove() })
            .on('video', { element: el => el.remove() })
            .on('audio', { element: el => el.remove() })
            .on('script', new AttributeRewriter('src', targetUrlStr))
            .on('iframe', new AttributeRewriter('src', targetUrlStr))
            .on('head', {
              element(element) {
                // Inject JS Hook for fetch/XHR
                const jsHook = `
                <script>
                  (function() {
                    const XOR_KEY = "${XOR_KEY}";
                    const PARAM_URL = "${PARAM_URL}";
                    const PROXY_ORIGIN = window.location.origin;
                    const TARGET_BASE = "${targetUrlStr}";

                    function xorProcess(input) {
                      let result = '';
                      for (let i = 0; i < input.length; i++) {
                        result += String.fromCharCode(input.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
                      }
                      return result;
                    }
                    function obfuscate(url) {
                      const xored = xorProcess(url);
                      return Array.from(xored).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                    }

                    function resolveUrl(url) {
                      if (!url) return url;
                      if (url.startsWith(PROXY_ORIGIN)) return url;
                      if (url.startsWith('data:')) return url;
                      try {
                        const absolute = new URL(url, TARGET_BASE).href;
                        return PROXY_ORIGIN + '/?' + PARAM_URL + '=' + obfuscate(absolute);
                      } catch (e) {
                        return url;
                      }
                    }

                    const originalFetch = window.fetch;
                    window.fetch = function(input, init) {
                      let url = input;
                      if (typeof input === 'string') url = resolveUrl(input);
                      else if (input instanceof Request) url = resolveUrl(input.url);
                      return originalFetch(url, init);
                    };

                    const originalOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url, ...args) {
                      return originalOpen.call(this, method, resolveUrl(url), ...args);
                    };
                    console.log('Proxy JS Hooks Injected (NoImg Mode)');
                  })();
                </script>
                `;
                element.append(jsHook, { html: true });
              }
            });
        } else {
          // Normal Mode: Rewrite and Inject JS Hook
          rewriter = rewriter
            .on('img', new AttributeRewriter('src', targetUrlStr))
            .on('img', new AttributeRewriter('data-src', targetUrlStr))
            .on('img', new SrcSetRewriter(targetUrlStr))
            .on('source', new AttributeRewriter('src', targetUrlStr))
            .on('source', new SrcSetRewriter(targetUrlStr))
            .on('video', new AttributeRewriter('src', targetUrlStr))
            .on('video', new AttributeRewriter('poster', targetUrlStr))
            .on('audio', new AttributeRewriter('src', targetUrlStr))
            .on('iframe', new AttributeRewriter('src', targetUrlStr))
            .on('script', new AttributeRewriter('src', targetUrlStr))
            .on('object', new AttributeRewriter('data', targetUrlStr))
            .on('embed', new AttributeRewriter('src', targetUrlStr))
            .on('track', new AttributeRewriter('src', targetUrlStr))
            .on('*', new AttributeRewriter('data-href', targetUrlStr))
            .on('*', new AttributeRewriter('data-url', targetUrlStr))
            .on('head', {
              element(element) {
                // Inject JS Hook for fetch/XHR
                const jsHook = `
                <script>
                  (function() {
                    const XOR_KEY = "${XOR_KEY}";
                    const PARAM_URL = "${PARAM_URL}";
                    const PROXY_ORIGIN = window.location.origin;
                    const TARGET_ORIGIN = "${targetUrl.origin}";
                    const TARGET_BASE = "${targetUrlStr}";

                    function xorProcess(input) {
                      let result = '';
                      for (let i = 0; i < input.length; i++) {
                        result += String.fromCharCode(input.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
                      }
                      return result;
                    }
                    function obfuscate(url) {
                      const xored = xorProcess(url);
                      return Array.from(xored).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                    }

                    function resolveUrl(url) {
                      if (!url) return url;
                      if (url.startsWith(PROXY_ORIGIN)) return url;
                      if (url.startsWith('data:')) return url;
                      
                      try {
                        const absolute = new URL(url, TARGET_BASE).href;
                        return PROXY_ORIGIN + '/?' + PARAM_URL + '=' + obfuscate(absolute);
                      } catch (e) {
                        return url;
                      }
                    }

                    const originalFetch = window.fetch;
                    window.fetch = function(input, init) {
                      let url = input;
                      if (typeof input === 'string') {
                        url = resolveUrl(input);
                      } else if (input instanceof Request) {
                        url = resolveUrl(input.url);
                      }
                      return originalFetch(url, init);
                    };

                    const originalOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url, ...args) {
                      return originalOpen.call(this, method, resolveUrl(url), ...args);
                    };

                    const originalOpenWindow = window.open;
                    window.open = function(url, target, features) {
                      if (url && typeof url === 'string') {
                        return originalOpenWindow(resolveUrl(url), target, features);
                      }
                      return originalOpenWindow(url, target, features);
                    };

                    const originalPushState = history.pushState;
                    history.pushState = function(state, unused, url) {
                       if (url) {
                         return originalPushState.apply(this, [state, unused, resolveUrl(url)]);
                       }
                       return originalPushState.apply(this, arguments);
                    };
                    
                    const originalReplaceState = history.replaceState;
                    history.replaceState = function(state, unused, url) {
                       if (url) {
                         return originalReplaceState.apply(this, [state, unused, resolveUrl(url)]);
                       }
                       return originalReplaceState.apply(this, arguments);
                    };

                    if (navigator.sendBeacon) {
                        const originalSendBeacon = navigator.sendBeacon;
                        navigator.sendBeacon = function(url, data) {
                            return originalSendBeacon.call(navigator, resolveUrl(url), data);
                        };
                    }

                    document.addEventListener('click', function(e) {
                      const link = e.target.closest('a');
                      if (link && link.href) {
                        const resolved = resolveUrl(link.href);
                        if (resolved !== link.href) {
                          e.preventDefault();
                          window.location.href = resolved;
                        }
                      }
                    }, true);

                    document.addEventListener('submit', function(e) {
                      const form = e.target;
                      const method = (form.getAttribute('method') || 'GET').toUpperCase();
                      
                      if (!form.querySelector('input[name="${PARAM_URL}"]')) {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = '${PARAM_URL}';
                        input.value = obfuscate(TARGET_BASE); 
                        
                        const action = form.getAttribute('action');
                        if (action) {
                           try {
                             const actionUrl = new URL(action, TARGET_BASE).href;
                             input.value = obfuscate(actionUrl);
                             if (method === 'GET') {
                               form.setAttribute('action', '/');
                             } else {
                               form.setAttribute('action', '/?' + '${PARAM_URL}=' + input.value);
                             }
                           } catch(e) {}
                        } else {
                           if (method === 'GET') form.setAttribute('action', '/');
                        }
                        
                        form.appendChild(input);
                      }
                    }, true);
                    
                    console.log('Proxy JS Hooks Injected');
                  })();
                </script>
                `;
                element.append(jsHook, { html: true });
              }
            });
        }
        
        return rewriter.transform(newResponse);
      }

      return newResponse;
    } catch (e) {
      return new Response(`Proxy Error: ${e}`, { status: 500 });
    }
  },
};
