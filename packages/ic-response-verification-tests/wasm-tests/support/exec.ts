import { execSync } from 'node:child_process';
import { resolve } from 'node:path';

export function execWithLogs(cmd: string, cwd?: string): void {
  execSync(cmd, { stdio: 'inherit', cwd });
}

export function exec(cmd: string, cwd?: string): string {
  const result = execSync(cmd, { cwd });

  return result.toString().replace(/(\r\n|\n|\r)/gm, '');
}

async function readFileBytes(filepath: string): Promise<Uint8Array> {
  filepath = resolve(import.meta.dir, filepath);
  const file = Bun.file(filepath);

  const buffer = await file.arrayBuffer();
  return new Uint8Array(buffer);
}

export async function readAsset(path: string): Promise<Uint8Array> {
  return await readFileBytes(`../../dfx-project/dist/frontend/${path}`);
}
