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
      const extractUrlOnly = body.extract_url_only === true || body.extract_url_only === 'true';
      const meta: DownloadJob = {
        job_id: jobId,
        video_url: body.url,
        format: body.format || body.f || 'best',
        audio_only: !!body.audio_only,
        extract_url_only: extractUrlOnly,
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
              extract_url_only: extractUrlOnly,
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
      if (body.extract_url_only) metaObj.extract_url_only = true;
      if (body.extracted_urls) metaObj.extracted_urls = body.extracted_urls;

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

  // GET /api/hls-proxy?url=... -> Proxy HLS manifests and segments to bypass CORS
  if (pathname === '/api/hls-proxy' && request.method === 'GET') {
    const targetUrl = url.searchParams.get('url');
    if (!targetUrl) {
      return new Response(JSON.stringify({ error: 'url parameter required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    try {
      // Validate URL is from Google/YouTube
      const targetUrlObj = new URL(targetUrl);
      const allowedHosts = ['googlevideo.com', 'youtube.com', 'ytimg.com', 'ggpht.com'];
      const isAllowed = allowedHosts.some(host => targetUrlObj.hostname.endsWith(host));
      
      if (!isAllowed) {
        return new Response(JSON.stringify({ error: 'URL not allowed' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
      }

      // Fetch the resource
      const proxyResponse = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Origin': 'https://www.youtube.com',
          'Referer': 'https://www.youtube.com/',
        },
      });

      if (!proxyResponse.ok) {
        return new Response(JSON.stringify({ error: `Upstream error: ${proxyResponse.status}` }), { 
          status: proxyResponse.status, 
          headers: { 'Content-Type': 'application/json' } 
        });
      }

      const contentType = proxyResponse.headers.get('Content-Type') || 'application/octet-stream';
      let body: string | ArrayBuffer;
      
      // If it's an m3u8 playlist, rewrite URLs to go through proxy
      if (contentType.includes('mpegurl') || targetUrl.includes('.m3u8') || contentType.includes('text')) {
        const text = await proxyResponse.text();
        const proxyBase = `${url.origin}/api/hls-proxy?url=`;
        
        // Rewrite URLs in playlist
        const rewritten = text.split('\n').map(line => {
          const trimmed = line.trim();
          if (trimmed.startsWith('#')) return line;
          if (trimmed.startsWith('http')) {
            return proxyBase + encodeURIComponent(trimmed);
          }
          if (trimmed && !trimmed.startsWith('#')) {
            // Relative URL
            const baseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);
            return proxyBase + encodeURIComponent(baseUrl + trimmed);
          }
          return line;
        }).join('\n');
        
        body = rewritten;
      } else {
        body = await proxyResponse.arrayBuffer();
      }

      return new Response(body, {
        status: 200,
        headers: {
          'Content-Type': contentType,
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Cache-Control': 'no-cache',
        },
      });
    } catch (e: any) {
      console.log('[HLS Proxy] Error:', e.message || e);
      return new Response(JSON.stringify({ error: e.message || String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // OPTIONS for CORS preflight
  if (pathname === '/api/hls-proxy' && request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
    });
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

  // DELETE /api/download/delete/:jobId or POST /api/download/delete
  if (pathname.startsWith('/api/download/delete') && (request.method === 'DELETE' || request.method === 'POST')) {
    let jobId = '';
    
    // Get job_id from URL path or request body
    const parts = pathname.split('/').filter(Boolean);
    if (parts.length >= 4) {
      jobId = parts[3];
    }
    
    if (!jobId && request.method === 'POST') {
      try {
        const body = await request.json().catch(() => null) as any;
        if (body && body.job_id) jobId = body.job_id;
      } catch (e) { /* ignore */ }
    }
    
    if (!jobId) {
      return new Response(JSON.stringify({ error: 'job_id required' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    try {
      // List all objects with prefix videos/{jobId}/
      const prefix = `videos/${jobId}/`;
      const listResult = await env.VIDEOS_BUCKET.list({ prefix });
      const objects = listResult.objects || [];
      
      if (objects.length === 0) {
        return new Response(JSON.stringify({ error: 'job not found', job_id: jobId }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      }
      
      // Delete all objects
      const deletePromises = objects.map(obj => env.VIDEOS_BUCKET.delete(obj.key));
      await Promise.all(deletePromises);
      
      console.log('[DownloadAPI] Deleted', objects.length, 'objects for job:', jobId);
      
      return new Response(JSON.stringify({ ok: true, job_id: jobId, deleted_count: objects.length }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e: any) {
      console.log('[DownloadAPI] Delete error:', e.message || e);
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
    // /api/download endpoints need to be accessible without login
    if (pathname === '/api/download' || pathname.startsWith('/api/download/')) {
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
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: "Hiragino Kaku Gothic ProN", "Noto Sans JP", Meiryo, sans-serif; 
      background: #f8f9fc;
      color: #374151;
      min-height: 100vh;
      line-height: 1.6;
    }
    
    /* Glass morphism header */
    .header {
      background: rgba(255, 255, 255, 0.85);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid rgba(0, 0, 0, 0.06);
      padding: 16px 24px;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .header-inner {
      max-width: 1000px;
      margin: 0 auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header-title {
      font-size: 18px;
      font-weight: 700;
      color: #1f2937;
    }
    .header-nav a {
      color: #6b7280;
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      padding: 8px 16px;
      border-radius: 8px;
      transition: all 0.2s;
    }
    .header-nav a:hover {
      background: #f3f4f6;
      color: #374151;
    }
    
    .wrapper { 
      max-width: 1000px; 
      margin: 0 auto; 
      padding: 32px 24px;
    }
    
    /* Card styles - clean and minimal */
    .card {
      background: #fff;
      border-radius: 16px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04), 0 4px 12px rgba(0, 0, 0, 0.03);
      margin-bottom: 24px;
      overflow: hidden;
      border: 1px solid rgba(0, 0, 0, 0.04);
    }
    .card-header {
      padding: 20px 24px;
      font-size: 15px;
      font-weight: 600;
      color: #374151;
      border-bottom: 1px solid #f3f4f6;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .card-header .icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
    }
    .card-header .icon.teal { background: #e0f7f4; color: #0d9488; }
    .card-header .icon.pink { background: #fce7f3; color: #db2777; }
    .card-header .icon.blue { background: #dbeafe; color: #2563eb; }
    .card-body { padding: 24px; }
    
    /* Stats grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
    }
    .stat-item {
      background: #f9fafb;
      border-radius: 12px;
      padding: 20px;
      text-align: center;
    }
    .stat-label {
      font-size: 12px;
      color: #6b7280;
      font-weight: 500;
      margin-bottom: 8px;
    }
    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: #1f2937;
    }
    .stat-sub {
      font-size: 11px;
      color: #9ca3af;
      margin-top: 4px;
    }
    .stat-bar {
      height: 4px;
      background: #e5e7eb;
      border-radius: 2px;
      margin-top: 12px;
      overflow: hidden;
    }
    .stat-bar-fill {
      height: 100%;
      border-radius: 2px;
      transition: width 0.3s;
    }
    .stat-bar-fill.green { background: #10b981; }
    .stat-bar-fill.yellow { background: #f59e0b; }
    .stat-bar-fill.red { background: #ef4444; }
    
    /* Form styles */
    .form-group { margin-bottom: 20px; }
    .form-group label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #374151;
      margin-bottom: 8px;
    }
    .form-group .checkbox-label {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 500;
      cursor: pointer;
      padding: 10px 12px;
      background: rgba(196, 181, 253, 0.1);
      border: 1px solid rgba(196, 181, 253, 0.3);
      border-radius: 10px;
      transition: all 0.2s;
    }
    .form-group .checkbox-label:hover {
      background: rgba(196, 181, 253, 0.2);
    }
    .form-group .checkbox-label input[type="checkbox"] {
      width: 18px;
      height: 18px;
      accent-color: #8b5cf6;
    }
    .form-group .checkbox-label span {
      font-size: 13px;
      color: #5b21b6;
    }
    .form-group input,
    .form-group select {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      font-size: 14px;
      color: #374151;
      background: #fff;
      transition: all 0.2s;
    }
    .form-group input:focus,
    .form-group select:focus {
      outline: none;
      border-color: #a7f3d0;
      box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
    }
    .form-group input::placeholder {
      color: #9ca3af;
    }
    
    /* Button styles */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 12px 24px;
      font-size: 14px;
      font-weight: 600;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-primary {
      background: linear-gradient(135deg, #34d399 0%, #10b981 100%);
      color: #fff;
      box-shadow: 0 2px 8px rgba(16, 185, 129, 0.25);
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(16, 185, 129, 0.35);
    }
    .btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .btn-secondary {
      background: #f3f4f6;
      color: #4b5563;
    }
    .btn-secondary:hover {
      background: #e5e7eb;
    }
    .btn-full { width: 100%; }
    
    /* Job list */
    .job-list { margin-top: 8px; }
    .job-item {
      padding: 20px;
      border: 1px solid #f3f4f6;
      border-radius: 12px;
      margin-bottom: 12px;
      background: #fff;
      transition: all 0.2s;
    }
    .job-item:hover {
      border-color: #e5e7eb;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
    }
    .job-item.completed { border-left: 3px solid #10b981; }
    .job-item.processing { border-left: 3px solid #3b82f6; }
    .job-item.pending { border-left: 3px solid #f59e0b; }
    .job-item.failed { border-left: 3px solid #ef4444; }
    
    .job-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .job-id {
      font-family: ui-monospace, monospace;
      font-size: 11px;
      color: #9ca3af;
      background: #f9fafb;
      padding: 4px 8px;
      border-radius: 6px;
    }
    .job-status {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .job-status.pending { background: #fef3c7; color: #b45309; }
    .job-status.processing { background: #dbeafe; color: #1d4ed8; }
    .job-status.completed { background: #d1fae5; color: #047857; }
    .job-status.failed { background: #fee2e2; color: #b91c1c; }
    
    .spinner {
      width: 12px;
      height: 12px;
      border: 2px solid currentColor;
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    
    .job-title {
      font-weight: 600;
      font-size: 14px;
      color: #1f2937;
      margin-bottom: 8px;
      word-break: break-all;
    }
    .job-meta {
      font-size: 12px;
      color: #6b7280;
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
    }
    .job-actions {
      margin-top: 16px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .btn-download {
      padding: 8px 16px;
      background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);
      color: #fff;
      border-radius: 8px;
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
    }
    .btn-download:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
    }
    .btn-delete {
      padding: 8px 16px;
      background: #fff;
      color: #ef4444;
      border: 1px solid #fecaca;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-delete:hover {
      background: #fef2f2;
      border-color: #ef4444;
    }
    .btn-copy {
      padding: 8px 16px;
      background: linear-gradient(135deg, #c4b5fd 0%, #ddd6fe 100%);
      color: #5b21b6;
      border: none;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(139, 92, 246, 0.3);
    }
    
    .extracted-urls {
      margin-top: 10px;
      padding: 12px;
      background: rgba(196, 181, 253, 0.15);
      border: 1px solid rgba(196, 181, 253, 0.3);
      border-radius: 10px;
    }
    .urls-label {
      font-size: 12px;
      color: #7c3aed;
      font-weight: 500;
      margin-bottom: 8px;
    }
    .url-item {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }
    .url-item:last-child { margin-bottom: 0; }
    .url-type {
      font-size: 11px;
      color: #8b5cf6;
      font-weight: 500;
      min-width: 40px;
    }
    .url-input {
      flex: 1;
      padding: 8px 10px;
      font-size: 11px;
      font-family: monospace;
      border: 1px solid rgba(196, 181, 253, 0.4);
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.8);
      color: #374151;
      cursor: text;
    }
    .url-input:focus {
      outline: none;
      border-color: #8b5cf6;
      box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2);
    }
    
    /* Video Player Modal */
    .video-player-container {
      margin-top: 12px;
      border-radius: 10px;
      overflow: hidden;
      background: #000;
    }
    .video-player {
      width: 100%;
      max-height: 300px;
      display: block;
    }
    .btn-play {
      background: linear-gradient(135deg, #10b981, #059669);
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-play:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
    }
    .btn-play::before {
      content: '▶';
      font-size: 10px;
    }
    .player-notice {
      font-size: 11px;
      color: #6b7280;
      margin-top: 8px;
      padding: 8px 10px;
      background: rgba(249, 250, 251, 0.8);
      border-radius: 6px;
    }
    .player-error {
      color: #dc2626;
      font-size: 12px;
      padding: 10px;
      background: #fef2f2;
      border-radius: 6px;
      margin-top: 8px;
    }
    
    .status-detail {
      font-size: 12px;
      color: #6b7280;
      margin-top: 8px;
      padding: 10px 14px;
      background: #f9fafb;
      border-radius: 8px;
    }
    .status-detail.error {
      background: #fef2f2;
      color: #b91c1c;
    }
    
    .progress-bar-container {
      height: 3px;
      background: #e5e7eb;
      border-radius: 2px;
      margin-top: 12px;
      overflow: hidden;
    }
    .progress-bar {
      height: 100%;
      background: linear-gradient(90deg, #60a5fa, #3b82f6);
      animation: progress-anim 1.5s ease-in-out infinite;
    }
    @keyframes progress-anim {
      0% { width: 0%; }
      50% { width: 70%; }
      100% { width: 100%; }
    }
    
    .empty-state {
      text-align: center;
      padding: 48px 24px;
      color: #9ca3af;
    }
    .empty-state .icon {
      font-size: 40px;
      margin-bottom: 16px;
      opacity: 0.5;
    }
    .loading {
      text-align: center;
      padding: 32px;
      color: #6b7280;
    }
    
    .msg {
      padding: 14px 18px;
      border-radius: 10px;
      margin-bottom: 16px;
      font-size: 14px;
    }
    .msg.success {
      background: #d1fae5;
      color: #047857;
    }
    .msg.error {
      background: #fee2e2;
      color: #b91c1c;
    }
    
    .hint {
      margin-top: 16px;
      padding: 14px 18px;
      background: #fefce8;
      border-radius: 10px;
      font-size: 12px;
      color: #a16207;
      line-height: 1.5;
    }
    
    @media (max-width: 640px) {
      .header-inner { flex-direction: column; gap: 12px; }
      .stats-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="header-inner">
      <div class="header-title">ダウンロード管理</div>
      <nav class="header-nav">
        <a href="/">ホーム</a>
      </nav>
    </div>
  </div>
  
  <div class="wrapper">
    <!-- Stats -->
    <div class="card">
      <div class="card-header">
        <span class="icon blue">S</span>
        使用状況
      </div>
      <div class="card-body">
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-label">R2 ストレージ</div>
            <div class="stat-value" id="r2-usage">--</div>
            <div class="stat-sub">無料枠: 10 GB</div>
            <div class="stat-bar"><div class="stat-bar-fill green" id="r2-bar" style="width: 0%"></div></div>
          </div>
          <div class="stat-item">
            <div class="stat-label">Actions 使用時間</div>
            <div class="stat-value" id="actions-usage">--</div>
            <div class="stat-sub">無料枠: 2,000 分</div>
            <div class="stat-bar"><div class="stat-bar-fill green" id="actions-bar" style="width: 0%"></div></div>
          </div>
          <div class="stat-item">
            <div class="stat-label">ジョブ数</div>
            <div class="stat-value" id="job-count">--</div>
            <div class="stat-sub">完了 / 処理中 / 失敗</div>
            <div class="stat-bar"><div class="stat-bar-fill green" id="job-bar" style="width: 0%"></div></div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- New Request -->
    <div class="card">
      <div class="card-header">
        <span class="icon teal">+</span>
        新規ダウンロード
      </div>
      <div class="card-body">
        <div id="form-message"></div>
        <form id="download-form">
          <div class="form-group">
            <label>YouTube URL</label>
            <input type="text" id="video-url" placeholder="https://www.youtube.com/watch?v=..." required>
          </div>
          <div class="form-group">
            <label>画質</label>
            <select id="format">
              <option value="720p">720p</option>
              <option value="480p">480p</option>
              <option value="360p">360p</option>
              <option value="bestaudio">音声のみ</option>
            </select>
          </div>
          <div class="form-group">
            <label class="checkbox-label">
              <input type="checkbox" id="extract-url-only">
              <span>URL抽出のみ（ダウンロードせずgooglevideo.comのURLを取得）</span>
            </label>
          </div>
          <button type="submit" class="btn btn-primary btn-full" id="submit-btn">
            ダウンロード開始
          </button>
        </form>
        <div class="hint">
          720p以下の画質に制限しています。処理には2〜5分かかります。<br>
          「URL抽出のみ」を選択すると、直接ダウンロードURLを取得できます（有効期限あり）。
        </div>
      </div>
    </div>
    
    <!-- Job List -->
    <div class="card">
      <div class="card-header">
        <span class="icon pink">H</span>
        履歴
        <button onclick="loadJobs()" class="btn btn-secondary" style="margin-left: auto; padding: 6px 12px; font-size: 12px;">更新</button>
      </div>
      <div class="card-body">
        <div id="job-list" class="job-list">
          <div class="loading">読み込み中...</div>
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
      submitBtn.textContent = '送信中...';
      
      const url = document.getElementById('video-url').value.trim();
      const format = document.getElementById('format').value;
      const extractUrlOnly = document.getElementById('extract-url-only').checked;
      
      try {
        const resp = await fetch('/api/download/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ 
            url, 
            format, 
            audio_only: format === 'bestaudio',
            extract_url_only: extractUrlOnly
          })
        });
        const data = await resp.json();
        if (resp.ok && data.job_id) {
          const modeText = extractUrlOnly ? 'URL抽出' : 'ダウンロード';
          formMsg.innerHTML = '<div class="msg success">' + modeText + 'リクエストを送信しました。Job ID: <code>' + data.job_id + '</code></div>';
          document.getElementById('video-url').value = '';
          loadJobs();
          startAutoRefresh();
        } else {
          formMsg.innerHTML = '<div class="msg error">エラー: ' + (data.error || '不明なエラー') + '</div>';
        }
      } catch (err) {
        formMsg.innerHTML = '<div class="msg error">通信エラー: ' + err.message + '</div>';
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'ダウンロード開始';
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
          const statusLabels = { pending: '待機中', processing: '処理中', completed: '完了', failed: '失敗' };
          const statusLabel = statusLabels[statusClass] || statusClass;
          const title = job.title || job.video_url || 'Unknown';
          const createdAt = job.created_at ? new Date(job.created_at).toLocaleString('ja-JP') : '-';
          
          let actionsHtml = '';
          let statusDetailHtml = '';
          let progressHtml = '';
          
          // Delete button for all jobs
          const deleteBtn = '<button class="btn-delete" onclick="deleteJob(\\'' + job.job_id + '\\')" title="削除">削除</button>';
          
          if (job.status === 'completed' && job.extract_url_only && job.extracted_urls) {
            // URL extraction mode - show extracted URLs
            const urls = job.extracted_urls.split('\\n').filter(u => u.trim() && u.startsWith('http'));
            let urlsHtml = '<div class="extracted-urls">';
            urlsHtml += '<div class="urls-label">抽出されたURL:</div>';
            urls.forEach((url, idx) => {
              const label = urls.length > 1 ? (idx === 0 ? '動画' : '音声') : 'URL';
              urlsHtml += '<div class="url-item"><span class="url-type">' + label + ':</span><input type="text" value="' + escapeHtml(url) + '" readonly onclick="this.select();" class="url-input"></div>';
            });
            urlsHtml += '<div id="player-' + job.job_id + '"></div>';
            urlsHtml += '</div>';
            statusDetailHtml = urlsHtml;
            actionsHtml = '<div class="job-actions"><button onclick="playVideo(\\'' + job.job_id + '\\')" class="btn-play">再生</button><button onclick="copyUrls(\\'' + job.job_id + '\\')" class="btn-copy">URLをコピー</button>' + deleteBtn + '</div>';
          } else if (job.status === 'completed' && job.filename) {
            actionsHtml = '<div class="job-actions"><a href="/video/' + job.job_id + '/' + encodeURIComponent(job.filename) + '" target="_blank" class="btn-download">ダウンロード</a>' + deleteBtn + '</div>';
          } else if (job.status === 'failed') {
            statusDetailHtml = '<div class="status-detail error">' + escapeHtml(job.error || '処理中にエラーが発生しました') + '</div>';
            actionsHtml = '<div class="job-actions">' + deleteBtn + '</div>';
          } else if (job.status === 'processing') {
            progressHtml = '<div class="progress-bar-container"><div class="progress-bar"></div></div>';
            statusDetailHtml = '<div class="status-detail">GitHub Actions でダウンロード処理中です...</div>';
            actionsHtml = '<div class="job-actions">' + deleteBtn + '</div>';
          } else if (job.status === 'pending') {
            statusDetailHtml = '<div class="status-detail">ジョブがキューに追加されました。まもなく処理が開始されます。</div>';
            actionsHtml = '<div class="job-actions">' + deleteBtn + '</div>';
          }
          
          const spinnerHtml = job.status === 'processing' ? '<div class="spinner"></div>' : '';
          
          return '<div class="job-item ' + statusClass + '">' +
            '<div class="job-header">' +
              '<span class="job-id">' + job.job_id + '</span>' +
              '<span class="job-status ' + statusClass + '">' + spinnerHtml + statusLabel + '</span>' +
            '</div>' +
            '<div class="job-title">' + escapeHtml(title) + '</div>' +
            '<div class="job-meta">' +
              '<span>' + createdAt + '</span>' +
              (job.format ? '<span>' + job.format + '</span>' : '') +
              (job.filesize ? '<span>' + formatBytes(job.filesize) + '</span>' : '') +
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
    
    // Store extracted URLs for copy function
    const extractedUrlsCache = {};
    
    async function copyUrls(jobId) {
      // Find the job and copy URLs
      try {
        const resp = await fetch('/api/download/status/' + jobId);
        const job = await resp.json();
        if (job.extracted_urls) {
          const urls = job.extracted_urls.split('\\n').filter(u => u.trim() && u.startsWith('http'));
          await navigator.clipboard.writeText(urls.join('\\n'));
          alert('URLをクリップボードにコピーしました');
        } else {
          alert('URLが見つかりません');
        }
      } catch (err) {
        // Fallback: select the input
        const inputs = document.querySelectorAll('.url-input');
        if (inputs.length > 0) {
          const urls = Array.from(inputs).map(i => i.value).join('\\n');
          try {
            await navigator.clipboard.writeText(urls);
            alert('URLをクリップボードにコピーしました');
          } catch (e) {
            alert('クリップボードへのコピーに失敗しました。手動でコピーしてください。');
          }
        }
      }
    }
    
    async function playVideo(jobId) {
      const playerContainer = document.getElementById('player-' + jobId);
      if (!playerContainer) return;
      
      // Toggle: if already has video, remove it
      if (playerContainer.innerHTML) {
        playerContainer.innerHTML = '';
        return;
      }
      
      try {
        const resp = await fetch('/api/download/status/' + jobId);
        const job = await resp.json();
        if (!job.extracted_urls) {
          playerContainer.innerHTML = '<div class="player-error">URLが見つかりません</div>';
          return;
        }
        
        const urls = job.extracted_urls.split('\\n').filter(u => u.trim() && u.startsWith('http'));
        if (urls.length === 0) {
          playerContainer.innerHTML = '<div class="player-error">有効なURLがありません</div>';
          return;
        }
        
        const videoUrl = urls[0];
        const isHLS = videoUrl.includes('.m3u8') || videoUrl.includes('manifest');
        
        // Use HLS proxy to bypass CORS
        const proxyUrl = '/api/hls-proxy?url=' + encodeURIComponent(videoUrl);
        
        if (isHLS) {
          // HLS stream - need HLS.js or native support
          playerContainer.innerHTML = \`
            <div class="video-player-container">
              <video id="video-\${jobId}" class="video-player" controls playsinline></video>
            </div>
            <div class="player-notice">プロキシ経由でHLSストリームを再生中...</div>
          \`;
          
          const video = document.getElementById('video-' + jobId);
          
          // Check for native HLS support (Safari)
          if (video.canPlayType('application/vnd.apple.mpegurl')) {
            video.src = proxyUrl;
            video.play().catch(e => console.log('Autoplay blocked:', e));
          } else {
            // Load HLS.js dynamically
            if (typeof Hls === 'undefined') {
              const script = document.createElement('script');
              script.src = 'https://cdn.jsdelivr.net/npm/hls.js@latest';
              script.onload = () => initHLS(video, proxyUrl);
              document.head.appendChild(script);
            } else {
              initHLS(video, proxyUrl);
            }
          }
        } else {
          // Direct video URL - also use proxy
          playerContainer.innerHTML = \`
            <div class="video-player-container">
              <video class="video-player" controls playsinline>
                <source src="\${escapeHtml(proxyUrl)}" type="video/mp4">
                お使いのブラウザはこの動画形式をサポートしていません。
              </video>
            </div>
            <div class="player-notice">プロキシ経由で再生中...</div>
          \`;
          const video = playerContainer.querySelector('video');
          video.play().catch(e => console.log('Autoplay blocked:', e));
        }
      } catch (err) {
        playerContainer.innerHTML = '<div class="player-error">エラー: ' + err.message + '</div>';
      }
    }
    
    function initHLS(video, url) {
      if (Hls.isSupported()) {
        const hls = new Hls({
          enableWorker: true,
          lowLatencyMode: true,
        });
        hls.loadSource(url);
        hls.attachMedia(video);
        hls.on(Hls.Events.MANIFEST_PARSED, () => {
          video.play().catch(e => console.log('Autoplay blocked:', e));
        });
        hls.on(Hls.Events.ERROR, (event, data) => {
          console.error('HLS error:', data);
          if (data.fatal) {
            const container = video.parentElement.parentElement;
            const notice = container.querySelector('.player-notice');
            if (notice) {
              notice.innerHTML = '<span style="color:#dc2626">HLS再生エラー: ' + (data.details || 'Unknown error') + '<br>URLをコピーしてVLC等で再生してください。</span>';
            }
          }
        });
      } else {
        const container = video.parentElement.parentElement;
        container.innerHTML = '<div class="player-error">お使いのブラウザはHLSをサポートしていません。URLをコピーしてVLC等で再生してください。</div>';
      }
    }
    
    async function deleteJob(jobId) {
      if (!confirm('このジョブを削除しますか？\\n\\nJob ID: ' + jobId + '\\n\\n※ 動画ファイルも削除されます')) return;
      
      try {
        const resp = await fetch('/api/download/delete/' + jobId, {
          method: 'DELETE',
          credentials: 'same-origin'
        });
        const data = await resp.json();
        if (resp.ok && data.ok) {
          loadJobs();
        } else {
          alert('削除エラー: ' + (data.error || '不明なエラー'));
        }
      } catch (err) {
        alert('通信エラー: ' + err.message);
      }
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
                background: linear-gradient(160deg, #f0f4f8 0%, #e8eef5 50%, #f5f0fa 100%);
                color: #374151; 
                min-height: 100vh;
            }
            .wrapper { width: 100%; max-width: 1100px; margin: 0 auto; }
            
            /* Header */
            .pos-header { 
                background: rgba(255,255,255,0.85);
                backdrop-filter: blur(20px);
                -webkit-backdrop-filter: blur(20px);
                padding: 15px 30px; 
                border-bottom: 1px solid rgba(148,163,184,0.2);
                display: flex; 
                align-items: center; 
                justify-content: space-between;
                box-shadow: 0 4px 20px rgba(0,0,0,0.03);
            }
            .pos-header-logo { 
                font-size: 22px; 
                font-weight: 600; 
                color: #64748b; 
                display: flex; 
                align-items: center; 
                gap: 12px;
                letter-spacing: 0.5px;
            }
            .header-links { font-size: 13px; color: #64748b; }
            .header-links a { 
                color: #64748b; 
                text-decoration: none; 
                padding: 8px 14px;
                border-radius: 8px;
                transition: all 0.2s;
                margin-left: 4px;
            }
            .header-links a:hover { 
                background: rgba(148,163,184,0.15); 
                color: #475569;
            }
            
            /* Main Body */
            .pos-body { 
                padding: 40px 20px 60px; 
                display: flex; 
                justify-content: center; 
                gap: 24px;
                flex-wrap: wrap;
            }
            
            /* Cards */
            .card {
                background: rgba(255,255,255,0.85);
                backdrop-filter: blur(20px);
                -webkit-backdrop-filter: blur(20px);
                border-radius: 20px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.06);
                border: 1px solid rgba(148,163,184,0.15);
                overflow: hidden;
                transition: transform 0.3s, box-shadow 0.3s;
            }
            .card:hover {
                transform: translateY(-2px);
                box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            }
            .card-header {
                padding: 18px 24px;
                font-size: 15px;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 10px;
                border-bottom: 1px solid rgba(148,163,184,0.1);
            }
            .card-body { padding: 24px; }
            
            /* Main Card */
            .main-card { flex: 1; min-width: 400px; max-width: 600px; }
            .main-card .card-header { 
                background: linear-gradient(135deg, rgba(134,239,172,0.3) 0%, rgba(167,243,208,0.2) 100%);
                color: #166534;
            }
            
            /* Side Card */
            .side-card { width: 350px; }
            .side-card .card-header {
                background: linear-gradient(135deg, rgba(253,186,116,0.3) 0%, rgba(254,215,170,0.2) 100%);
                color: #9a3412;
            }
            .side-card.bookmarks .card-header {
                background: linear-gradient(135deg, rgba(196,181,253,0.3) 0%, rgba(221,214,254,0.2) 100%);
                color: #5b21b6;
            }
            
            /* Input Styles */
            .input-group { margin-bottom: 20px; }
            .input-group label {
                display: block;
                font-weight: 500;
                margin-bottom: 8px;
                font-size: 13px;
                color: #64748b;
            }
            .input-group input[type="text"] {
                width: 100%;
                padding: 14px 16px;
                border: 1px solid rgba(148,163,184,0.3);
                border-radius: 12px;
                font-size: 15px;
                transition: all 0.3s;
                background: rgba(255,255,255,0.7);
            }
            .input-group input[type="text"]:focus {
                outline: none;
                border-color: #86efac;
                background: #fff;
                box-shadow: 0 0 0 4px rgba(134,239,172,0.2);
            }
            
            /* Options */
            .options-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 10px;
                margin: 20px 0;
                padding: 18px;
                background: rgba(248,250,252,0.8);
                border-radius: 14px;
                border: 1px solid rgba(148,163,184,0.1);
            }
            .option-item {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 10px 12px;
                background: rgba(255,255,255,0.8);
                border-radius: 10px;
                cursor: pointer;
                transition: all 0.2s;
                border: 1px solid transparent;
            }
            .option-item:hover { 
                border-color: rgba(134,239,172,0.5);
                background: rgba(255,255,255,0.95);
            }
            .option-item input[type="checkbox"] {
                width: 18px;
                height: 18px;
                accent-color: #22c55e;
            }
            .option-item span { font-size: 13px; color: #64748b; }
            
            /* Buttons */
            .btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: 500;
                border: none;
                border-radius: 12px;
                cursor: pointer;
                transition: all 0.3s;
            }
            .btn-primary {
                background: linear-gradient(135deg, #86efac 0%, #a7f3d0 100%);
                color: #166534;
                box-shadow: 0 4px 15px rgba(134,239,172,0.3);
            }
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(134,239,172,0.4);
            }
            .btn-secondary {
                background: linear-gradient(135deg, #fdba74 0%, #fed7aa 100%);
                color: #9a3412;
                box-shadow: 0 4px 15px rgba(253,186,116,0.3);
            }
            .btn-secondary:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(253,186,116,0.4);
            }
            .btn-outline {
                background: rgba(255,255,255,0.8);
                color: #64748b;
                border: 1px solid rgba(148,163,184,0.3);
            }
            .btn-outline:hover {
                border-color: rgba(134,239,172,0.5);
                color: #166534;
                background: rgba(255,255,255,0.95);
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
                border: 1px solid rgba(148,163,184,0.3);
                border-radius: 10px;
                font-size: 14px;
                transition: all 0.3s;
                background: rgba(255,255,255,0.7);
            }
            .yt-input-row input:focus {
                outline: none;
                border-color: #fdba74;
                box-shadow: 0 0 0 4px rgba(253,186,116,0.2);
                background: #fff;
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
                background: rgba(255,255,255,0.8);
                border: 1px solid rgba(148,163,184,0.2);
                border-radius: 20px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s;
            }
            .yt-option:has(input:checked) {
                border-color: #fdba74;
                background: rgba(254,243,199,0.5);
            }
            .yt-option input { accent-color: #f97316; }
            
            /* Bookmarks */
            .bookmark-list { max-height: 200px; overflow-y: auto; }
            .bookmark-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 12px 15px;
                border-bottom: 1px solid rgba(148,163,184,0.1);
                transition: background 0.2s;
            }
            .bookmark-item:hover { background: rgba(248,250,252,0.8); }
            .bookmark-item:last-child { border-bottom: none; }
            .bookmark-item a {
                color: #7c3aed;
                text-decoration: none;
                font-weight: 500;
                font-size: 14px;
            }
            .bookmark-item a:hover { text-decoration: underline; }
            .bookmark-delete {
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(248,250,252,0.8);
                border-radius: 50%;
                color: #94a3b8;
                cursor: pointer;
                transition: all 0.2s;
            }
            .bookmark-delete:hover { 
                background: rgba(254,226,226,0.8); 
                color: #dc2626; 
            }
            .bookmark-empty {
                padding: 30px;
                text-align: center;
                color: #94a3b8;
                font-size: 13px;
            }
            
            /* Footer */
            .pos-footer { 
                text-align: center; 
                padding: 25px; 
                font-size: 12px; 
                color: #94a3b8; 
                background: rgba(255,255,255,0.6);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border-top: 1px solid rgba(148,163,184,0.1);
            }
            
            /* Notice */
            .notice {
                margin-top: 20px;
                padding: 15px;
                background: rgba(248,250,252,0.8);
                border: 1px solid rgba(148,163,184,0.1);
                border-radius: 12px;
                font-size: 12px;
                color: #64748b;
                line-height: 1.6;
            }
            .notice strong { color: #dc2626; }
            
            /* Title Input Special */
            .title-input-wrapper {
                margin-top: 15px;
                padding: 15px;
                background: rgba(255,255,255,0.6);
                border-radius: 10px;
            }
            .title-input-wrapper label {
                font-size: 12px;
                color: #64748b;
                margin-bottom: 6px;
                display: block;
            }
            .title-input-wrapper input {
                width: 100%;
                padding: 10px 12px;
                border: 1px solid rgba(148,163,184,0.3);
                border-radius: 8px;
                font-size: 13px;
                background: rgba(255,255,255,0.8);
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
            document.querySelector('#yt-progress-overlay > div > div:first-child').textContent = '▶';
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
                list.innerHTML = '<div class="bookmark-empty">ブックマークはありません<br><small>URLを入力してブックマークボタンで追加</small></div>';
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
              <a href="/downloads">ダウンロード管理</a>
              <a href="#">利用ガイド</a>
              <a href="#">FAQ</a>
            </div>
          </div>
          
          <div class="pos-body">
            <!-- Main Card: Proxy -->
            <div class="card main-card">
              <div class="card-header">
                Web Proxy - プロキシ接続
              </div>
              <div class="card-body">
                <form onsubmit="event.preventDefault(); go();">
                  <div class="input-group">
                    <label>URL / 検索キーワード</label>
                    <input type="text" id="url" placeholder="https://example.com または 検索ワード" required>
                  </div>
                  
                  <div class="options-grid">
                    <label class="option-item">
                      <input type="checkbox" id="lite" onchange="if(this.checked) document.getElementById('noimg').checked=false">
                      <span>軽量モード</span>
                    </label>
                    <label class="option-item">
                      <input type="checkbox" id="noimg" onchange="if(this.checked) document.getElementById('lite').checked=false">
                      <span>画像なし</span>
                    </label>
                    <label class="option-item">
                      <input type="checkbox" id="mobile">
                      <span>モバイル偽装</span>
                    </label>
                    <div class="title-input-wrapper" style="grid-column: 1 / -1;">
                      <label>表示タイトル（偽装用）</label>
                      <input type="text" id="title" placeholder="任意のタイトル" value="東進学力ＰＯＳ">
                    </div>
                  </div>

                  <div class="btn-group">
                    <button type="submit" class="btn btn-primary">アクセス開始</button>
                    <button type="button" onclick="goDuck()" class="btn btn-secondary">DuckDuckGo</button>
                    <button type="button" onclick="addBookmark()" class="btn btn-outline">ブックマーク追加</button>
                  </div>
                </form>
                
                <div class="notice">
                  URLを入力するとプロキシ経由でアクセス、キーワードを入力するとGoogle検索を実行します。<br>
                  緊急時は <strong>Escキーを3回連打</strong> でGoogleへ移動します。
                </div>
              </div>
            </div>
            
            <!-- Side Cards -->
            <div style="display: flex; flex-direction: column; gap: 20px; width: 350px;">
              <!-- YouTube Card -->
              <div class="card side-card">
                <div class="card-header">
                  YouTube ダウンロード
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
                      <input type="radio" name="ytformat" value="video"> 動画
                    </label>
                    <label class="yt-option">
                      <input type="radio" name="ytformat" value="audio"> 音声
                    </label>
                    <label class="yt-option">
                      <input type="radio" name="ytformat" value="best"> 最高画質
                    </label>
                  </div>
                  
                  <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(148,163,184,0.15);">
                    <div style="font-size: 12px; color: #64748b; margin-bottom: 8px;">API選択:</div>
                    <div class="yt-options" style="flex-wrap: wrap;">
                      <label class="yt-option" style="border-color: rgba(134,239,172,0.5);">
                        <input type="radio" name="ytapi" value="auto" checked> 自動
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="piped"> Piped
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="invidious"> Invidious
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="vevioz"> Vevioz
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="cobalt"> Cobalt
                      </label>
                      <label class="yt-option">
                        <input type="radio" name="ytapi" value="y2mate"> Y2Mate
                      </label>
                      <label class="yt-option" style="border-color: rgba(244,114,182,0.5); background: rgba(252,231,243,0.5);">
                        <input type="radio" name="ytapi" value="allscan"> 全取得
                      </label>
                    </div>
                    <div style="font-size: 10px; color: #f472b6; margin-top: 5px; text-align: center;">
                      ※ 全取得: すべてのAPIを回して全フォーマットを表示
                    </div>
                  </div>
                  
                  <div style="font-size: 11px; color: #94a3b8; text-align: center; margin-top: 10px;">
                    youtube.com, youtu.be, shorts に対応
                  </div>
                </div>
              </div>
              
              <!-- Cobalt Card -->
              <div class="card side-card" style="border-top: none;">
                <div class="card-header" style="background: linear-gradient(135deg, rgba(196,181,253,0.3) 0%, rgba(221,214,254,0.2) 100%); color: #5b21b6;">
                  その他サイト (Cobalt)
                </div>
                <div class="card-body">
                  <div class="yt-input-row">
                    <input type="text" id="cobalturl" placeholder="Twitter, TikTok, Instagram...">
                    <button type="button" onclick="goCobalt()" class="btn" style="padding: 12px 20px; white-space: nowrap; background: linear-gradient(135deg, rgba(196,181,253,0.8) 0%, rgba(221,214,254,0.8) 100%); color: #5b21b6;">取得</button>
                  </div>
                  <div style="font-size: 11px; color: #94a3b8; text-align: center; line-height: 1.5;">
                    Twitter/X, TikTok, Instagram, Vimeo,<br>SoundCloud, Reddit, Tumblr 等
                  </div>
                </div>
              </div>
              
              <!-- Bookmarks Card -->
              <div class="card side-card bookmarks">
                <div class="card-header">
                  ブックマーク
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
          <div id="yt-progress-overlay" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15,23,42,0.6); justify-content: center; align-items: center; z-index: 9999; backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);">
            <div style="background: rgba(255,255,255,0.95); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 50px 60px; border-radius: 24px; text-align: center; box-shadow: 0 25px 80px rgba(0,0,0,0.15); min-width: 380px; border: 1px solid rgba(148,163,184,0.1);">
              <div style="font-size: 48px; margin-bottom: 20px; color: #64748b;">&#9654;</div>
              <div style="font-size: 18px; font-weight: 500; color: #374151; margin-bottom: 25px;">ダウンロード準備中</div>
              <div style="background: rgba(241,245,249,0.8); border-radius: 12px; height: 8px; overflow: hidden; margin-bottom: 20px;">
                <div id="yt-progress-bar" style="background: linear-gradient(90deg, #86efac, #a7f3d0); height: 100%; width: 0%; transition: width 0.4s ease; border-radius: 12px;"></div>
              </div>
              <div id="yt-progress-status" style="color: #64748b; font-size: 14px; margin-bottom: 25px;">準備中...</div>
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
