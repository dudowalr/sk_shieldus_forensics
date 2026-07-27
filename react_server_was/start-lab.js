'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const NEXT_HOST = process.env.REACT_UPSTREAM_HOST || '127.0.0.1';
const NEXT_PORT = process.env.REACT_UPSTREAM_PORT || '3001';
const nextCli = path.join(
  __dirname,
  'node_modules',
  'next',
  'dist',
  'bin',
  'next',
);
const loggerScript = path.join(__dirname, 'logger-proxy.js');

for (const requiredFile of [nextCli, loggerScript]) {
  if (!fs.existsSync(requiredFile)) {
    console.error(`Required file not found: ${requiredFile}`);
    process.exit(1);
  }
}

function startChild(name, script, args) {
  console.log(`[launcher] starting ${name}`);
  const child = spawn(process.execPath, [script, ...args], {
    cwd: __dirname,
    env: process.env,
    stdio: 'inherit',
    windowsHide: true,
  });

  return { name, child };
}

const children = [
  startChild('Next.js', nextCli, [
    'start',
    '-H',
    NEXT_HOST,
    '-p',
    NEXT_PORT,
  ]),
  startChild('HTTP logger', loggerScript, []),
];

let shuttingDown = false;
let finalExitCode = 0;
let remainingChildren = children.length;

function stopChildren(exitCode, reason) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  finalExitCode = exitCode;
  console.log(`[launcher] stopping lab: ${reason}`);

  for (const { child } of children) {
    if (child.exitCode === null && !child.killed) {
      child.kill();
    }
  }

  setTimeout(() => {
    process.exit(finalExitCode);
  }, 5000).unref();
}

for (const { name, child } of children) {
  child.once('error', (error) => {
    console.error(`[launcher] ${name} failed to start:`, error);
    stopChildren(1, `${name} start failure`);
  });

  child.once('exit', (code, signal) => {
    remainingChildren -= 1;
    console.log(
      `[launcher] ${name} exited` +
        ` code=${code === null ? 'null' : code}` +
        ` signal=${signal || 'none'}`,
    );

    if (!shuttingDown) {
      stopChildren(code === 0 ? 0 : 1, `${name} exited`);
    }

    if (remainingChildren === 0) {
      process.exit(finalExitCode);
    }
  });
}

process.once('SIGINT', () => stopChildren(0, 'Ctrl+C'));
process.once('SIGTERM', () => stopChildren(0, 'SIGTERM'));