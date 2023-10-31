import { exec, execWithLogs } from './exec';

function getReplicaPort(): string {
  return exec('dfx info replica-port');
}

export function getReplicaUrl(): string {
  const port = getReplicaPort();

  return `http://localhost:${port}`;
}

function startDfx(): void {
  execWithLogs('dfx start --background');
}

export function stopDfx(): void {
  execWithLogs('dfx stop');
}

export function restartDfx(): void {
  stopDfx();
  startDfx();
}

export function dfxDeploy(
  canisterName: string,
  projectDirectory: string,
): string {
  execWithLogs(`dfx deploy ${canisterName}`, projectDirectory);
  return exec(`dfx canister id ${canisterName}`, projectDirectory);
}
