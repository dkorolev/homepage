import { randomInt } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const nameSchema = z.string().trim().min(1).max(60).refine(value => !/[\p{Cc}\p{Cf}]/u.test(value), 'Use a printable name.');
const palette = [
  ['Coral', '#EF6A5B'], ['Cobalt', '#4169E1'], ['Jade', '#168A68'],
  ['Violet', '#8655C7'], ['Amber', '#BC7909'], ['Rose', '#C44275'], ['Teal', '#087F8C'],
];

export function colorBoard() {
  const latest = [];
  return {
    latest: () => latest.map(item => ({ ...item })),
    assign(name) {
      name = nameSchema.parse(name);
      const [color, hex] = palette[randomInt(palette.length)];
      const assignment = { name, color, hex, assigned_at: new Date().toISOString() };
      latest.unshift(assignment);
      latest.splice(5);
      return { assignment, latest: this.latest() };
    },
  };
}

export function createMcp(board) {
  const server = new McpServer({ name: 'current-colors', version: '1.0.0' });
  const result = value => ({ content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value });
  server.registerTool('assign_color', {
    title: 'Give a name a color',
    description: 'Assign a random color to a name. The name and color become public in the latest five entries on current.ai. No authentication required.',
    inputSchema: { name: nameSchema.describe('A public display name, at most 60 characters. Do not submit private information.') },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, async ({ name }) => result(board.assign(name)));
  server.registerTool('latest_colors', {
    title: 'See the latest five colors', description: 'Read the five most recent public name and color assignments.',
    inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => result({ latest: board.latest() }));
  server.registerResource('latest-colors', 'current://colors/latest', {
    title: 'Latest five colors', mimeType: 'application/json',
  }, async uri => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(board.latest()) }] }));
  return server;
}

export function mountMcp(app, board, origin, jsonBody, limiter) {
  app.use('/mcp', (req, res, next) => {
    if (req.get('origin') && req.get('origin') !== origin) return res.status(403).json({ error: 'Origin not allowed' });
    next();
  });
  app.post('/mcp', limiter, jsonBody, async (req, res) => {
    const server = createMcp(board);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => { void transport.close(); void server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  app.all('/mcp', (_req, res) => res.set('Allow', 'POST').status(405).end());
}
