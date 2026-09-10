export function escape(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}

export function form(action, csrf, body) {
  return `<form method="post" action="${escape(action)}"><input type="hidden" name="csrf" value="${escape(csrf)}">${body}</form>`;
}

export function page(title, body, origin = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${escape(title)} · Current</title><link rel="icon" type="image/svg+xml" href="/static/favicon.svg" sizes="any"><link rel="stylesheet" href="${escape(origin)}/assets/prnui.css"><link rel="stylesheet" href="${escape(origin)}/assets/style.css"></head><body class="current-site"><header class="site-header"><a class="wordmark" href="https://github.com/c5t/current">current<span>↗</span></a><nav aria-label="Main navigation"><a href="${escape(origin)}/#demos">Demos</a><a href="${escape(origin)}/setup">Build with Current</a><a href="${escape(origin)}/account">Your account</a></nav></header><main class="document"><article class="chamfer card card--accent-left accent-cyan document-panel">${body}</article></main><footer class="site-footer"><span>Current · Working experiments</span><div><a href="https://dima.ai">dima.ai ↗</a><a href="https://github.com/C5T/current">Current on GitHub ↗</a><a href="https://dima.ai/prn">PRN UI ↗</a></div></footer></body></html>`;
}
