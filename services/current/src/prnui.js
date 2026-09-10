import { readFile } from 'node:fs/promises';

export async function loadPrnuiCss() {
  // Consume the upstream specimen's styles without maintaining a second copy.
  const source = await readFile(new URL('../../../vendor/prnui/prnui.html', import.meta.url), 'utf8');
  const styles = [...source.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)].map(match => match[1]);
  if (!styles.length) throw new Error('The PRN UI submodule must contain the specimen stylesheet.');
  return styles.join('\n');
}
